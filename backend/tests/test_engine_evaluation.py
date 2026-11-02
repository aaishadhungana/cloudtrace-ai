from app.engine.models import Decision
from app.models.enums import RelationshipType
from engine_support import (
    allow,
    analyze_document,
    bucket,
    bucket_arn,
    deny,
    document,
    external_arn,
    external_principal,
    policy,
    principal_statement,
    relationship_between,
    role,
    role_arn,
    user,
    user_arn,
)

MFA = {"Bool": {"aws:MultiFactorAuthPresent": ["true"]}}
OBJECTS = f"{bucket_arn('reports')}/*"


def read_outcome(*statements):
    doc = document([user("u", ["p"])], [bucket("reports")], [policy("p", *statements)])
    relationship = relationship_between(
        analyze_document(doc), user_arn("u"), bucket_arn("reports"), RelationshipType.CAN_READ
    )
    return None if relationship is None else (relationship.effect, relationship.decision)


def test_matching_allow_is_allowed():
    assert read_outcome(allow(["s3:GetObject"], [OBJECTS])) == ("allow", Decision.ALLOWED)


def test_action_names_are_case_insensitive():
    assert read_outcome(allow(["s3:getobject"], [OBJECTS])) == ("allow", Decision.ALLOWED)


def test_missing_allow_is_an_implicit_deny():
    assert read_outcome(allow(["s3:GetObject"], [f"{bucket_arn('other')}/*"])) is None


def test_deny_without_allow_creates_no_relationship():
    assert read_outcome(deny(["s3:*"], ["*"])) is None


def test_explicit_deny_beats_allow_regardless_of_order():
    blocked = deny(["s3:*"], [bucket_arn("reports"), OBJECTS])
    grant = allow(["s3:*"], ["*"])
    assert read_outcome(grant, blocked) == ("deny", Decision.EXPLICITLY_DENIED)
    assert read_outcome(blocked, grant) == ("deny", Decision.EXPLICITLY_DENIED)


def test_explicit_deny_only_affects_the_denied_resource():
    doc = document(
        [user("u", ["p"])],
        [bucket("reports"), bucket("other")],
        [policy("p", allow(["s3:*"], ["*"]), deny(["s3:*"], [bucket_arn("reports"), OBJECTS]))],
    )
    result = analyze_document(doc)
    other = relationship_between(
        result, user_arn("u"), bucket_arn("other"), RelationshipType.CAN_READ
    )
    assert other is not None and other.decision is Decision.ALLOWED


def test_conditional_allow_is_conditional():
    assert read_outcome(allow(["s3:GetObject"], [OBJECTS], MFA)) == ("allow", Decision.CONDITIONAL)


def test_conditional_deny_does_not_block_but_makes_result_conditional():
    outcome = read_outcome(allow(["s3:*"], ["*"]), deny(["s3:*"], ["*"], MFA))
    assert outcome == ("allow", Decision.CONDITIONAL)


def test_object_actions_need_object_scope():
    assert read_outcome(allow(["s3:GetObject"], [bucket_arn("reports")])) is None


def test_bucket_actions_use_the_bucket_arn():
    assert read_outcome(allow(["s3:ListBucket"], [bucket_arn("reports")])) == (
        "allow",
        Decision.ALLOWED,
    )


def test_public_resource_policy_grants_every_identity():
    doc = document(
        [user("nobody")],
        [bucket("site", policy_statements=[principal_statement(["*"], ["s3:GetObject"])])],
    )
    relationship = relationship_between(
        analyze_document(doc), user_arn("nobody"), bucket_arn("site"), RelationshipType.CAN_READ
    )
    assert relationship is not None and relationship.decision is Decision.ALLOWED


def test_named_internal_principal_in_resource_policy_is_allowed():
    doc = document(
        [user("alice")],
        [
            bucket(
                "data",
                policy_statements=[principal_statement([user_arn("alice")], ["s3:GetObject"])],
            )
        ],
    )
    relationship = relationship_between(
        analyze_document(doc), user_arn("alice"), bucket_arn("data"), RelationshipType.CAN_READ
    )
    assert relationship is not None and relationship.decision is Decision.ALLOWED


def test_named_external_principal_in_resource_policy_is_conditional():
    doc = document(
        [user("alice"), external_principal()],
        [
            bucket(
                "data",
                policy_statements=[principal_statement([external_arn()], ["s3:GetObject"])],
            )
        ],
    )
    relationship = relationship_between(
        analyze_document(doc), external_arn(), bucket_arn("data"), RelationshipType.CAN_READ
    )
    assert relationship is not None and relationship.decision is Decision.CONDITIONAL
    assert relationship.notes


def test_public_resource_policy_is_allowed_for_external_principals():
    doc = document(
        [user("alice"), external_principal()],
        [bucket("site", policy_statements=[principal_statement(["*"], ["s3:GetObject"])])],
    )
    relationship = relationship_between(
        analyze_document(doc), external_arn(), bucket_arn("site"), RelationshipType.CAN_READ
    )
    assert relationship is not None and relationship.decision is Decision.ALLOWED


def assume(doc, source, target):
    return relationship_between(
        analyze_document(doc), source, target, RelationshipType.CAN_ASSUME
    )


def test_trust_policy_alone_allows_same_account_assumption():
    doc = document([user("u"), role("r", trusted=[user_arn("u")])])
    relationship = assume(doc, user_arn("u"), role_arn("r"))
    assert relationship is not None and relationship.decision is Decision.ALLOWED


def test_untrusted_identity_cannot_assume():
    doc = document([user("a"), user("b"), role("r", trusted=[user_arn("a")])])
    assert assume(doc, user_arn("b"), role_arn("r")) is None


def test_role_without_trust_policy_cannot_be_assumed():
    doc = document([user("u", ["p"]), role("r")], policies=[
        policy("p", allow(["sts:AssumeRole"], [role_arn("r")]))
    ])
    assert assume(doc, user_arn("u"), role_arn("r")) is None


def test_identity_side_deny_blocks_assumption():
    doc = document(
        [user("u", ["p"]), role("r", trusted=[user_arn("u")])],
        policies=[policy("p", deny(["sts:AssumeRole"], [role_arn("r")]))],
    )
    relationship = assume(doc, user_arn("u"), role_arn("r"))
    assert relationship is not None
    assert relationship.effect == "deny"
    assert relationship.decision is Decision.EXPLICITLY_DENIED


def test_trust_conditions_make_assumption_conditional():
    doc = document([user("u"), role("r", trusted=[user_arn("u")], trust_conditions=MFA)])
    relationship = assume(doc, user_arn("u"), role_arn("r"))
    assert relationship is not None and relationship.decision is Decision.CONDITIONAL


def test_wildcard_trust_allows_internal_identities():
    doc = document([user("u"), role("r", trusted=["*"])])
    relationship = assume(doc, user_arn("u"), role_arn("r"))
    assert relationship is not None and relationship.decision is Decision.ALLOWED


def test_external_principal_assumption_is_conditional():
    doc = document([external_principal(), role("r", trusted=[external_arn()])])
    relationship = assume(doc, external_arn(), role_arn("r"))
    assert relationship is not None and relationship.decision is Decision.CONDITIONAL


def test_policy_modification_relationships_include_self_and_others():
    doc = document(
        [user("a", ["p"]), user("b")],
        policies=[policy("p", allow(["iam:PutUserPolicy"], ["*"]))],
    )
    result = analyze_document(doc)
    modify = RelationshipType.CAN_MODIFY_POLICY
    assert relationship_between(result, user_arn("a"), user_arn("a"), modify) is not None
    assert relationship_between(result, user_arn("a"), user_arn("b"), modify) is not None
    assert relationship_between(result, user_arn("b"), user_arn("a"), modify) is None


def test_evaluation_is_deterministic():
    doc = document(
        [user("a", ["p"]), role("r", trusted=[user_arn("a")])],
        [bucket("one"), bucket("two", sensitive=True)],
        [policy("p", allow(["s3:*"], ["*"]))],
    )
    assert analyze_document(doc).relationships == analyze_document(doc).relationships