import pytest

from app.ingest.parser import ImportRejectedError
from app.ingest.pipeline import process_import
from app.samples.catalog import list_samples, read_sample
from support import encode_document, minimal_document


def rejection_messages(body: bytes) -> list[str]:
    with pytest.raises(ImportRejectedError) as raised:
        process_import(body)
    return [f"{issue.path}: {issue.message}" for issue in raised.value.issues]


def add_role(document, trust_statement):
    document["identities"].append(
        {
            "arn": "arn:aws:iam::111122223333:role/ops",
            "name": "ops",
            "type": "iam_role",
            "trust_policy": {"statements": [trust_statement]},
        }
    )


def test_every_bundled_sample_is_accepted():
    for sample in list_samples():
        assert process_import(read_sample(sample.name)).metadata["identity_count"] > 0


def test_minimal_document_is_accepted():
    normalized = process_import(encode_document(minimal_document()))
    assert normalized.metadata["identity_count"] == 1
    assert normalized.metadata["statement_count"] == 1


def test_unknown_field_is_rejected_instead_of_ignored():
    document = minimal_document()
    document["policies"][0]["statements"][0]["not_actions"] = ["s3:*"]
    messages = rejection_messages(encode_document(document))
    assert any("statements[0].not_actions" in item and "Unsupported or unknown" in item for item in messages)


def test_unsupported_schema_version_is_rejected():
    document = minimal_document()
    document["schema_version"] = "2.0"
    messages = rejection_messages(encode_document(document))
    assert any(item.startswith("schema_version") for item in messages)


def test_missing_schema_version_is_rejected():
    document = minimal_document()
    del document["schema_version"]
    messages = rejection_messages(encode_document(document))
    assert any(item.startswith("schema_version") for item in messages)


def test_duplicate_identity_arn_is_rejected():
    document = minimal_document()
    document["identities"].append(dict(document["identities"][0]))
    messages = rejection_messages(encode_document(document))
    assert any("Duplicate arn" in item for item in messages)


def test_arn_used_as_identity_and_resource_is_rejected():
    document = minimal_document()
    document["resources"][0]["arn"] = document["identities"][0]["arn"]
    messages = rejection_messages(encode_document(document))
    assert any("both an identity and a resource" in item for item in messages)


def test_unknown_policy_reference_is_rejected():
    document = minimal_document()
    document["identities"][0]["policy_ids"] = ["nope"]
    messages = rejection_messages(encode_document(document))
    assert any("unknown policy 'nope'" in item for item in messages)


def test_unknown_trust_principal_is_rejected():
    document = minimal_document()
    add_role(
        document,
        {
            "effect": "Allow",
            "principals": ["arn:aws:iam::111122223333:user/ghost"],
            "actions": ["sts:AssumeRole"],
        },
    )
    messages = rejection_messages(encode_document(document))
    assert any("not defined in identities" in item for item in messages)


def test_trust_policy_on_user_is_rejected():
    document = minimal_document()
    document["identities"][0]["trust_policy"] = {
        "statements": [
            {
                "effect": "Allow",
                "principals": ["arn:aws:iam::111122223333:user/alice"],
                "actions": ["sts:AssumeRole"],
            }
        ]
    }
    messages = rejection_messages(encode_document(document))
    assert any("only valid for identities of type 'iam_role'" in item for item in messages)


def test_trust_policy_with_other_actions_is_rejected():
    document = minimal_document()
    add_role(
        document,
        {
            "effect": "Allow",
            "principals": ["arn:aws:iam::111122223333:user/alice"],
            "actions": ["sts:AssumeRoleWithWebIdentity"],
        },
    )
    messages = rejection_messages(encode_document(document))
    assert any("only support 'sts:AssumeRole'" in item for item in messages)


def test_external_principal_cannot_have_policies():
    document = minimal_document()
    document["identities"].append(
        {
            "arn": "arn:aws:iam::999988887777:root",
            "name": "partner",
            "type": "external_principal",
            "policy_ids": ["read-reports"],
        }
    )
    messages = rejection_messages(encode_document(document))
    assert any("external principals" in item for item in messages)


def test_account_id_must_match_arn():
    document = minimal_document()
    document["identities"][0]["account_id"] = "999988887777"
    messages = rejection_messages(encode_document(document))
    assert any("does not match the account" in item for item in messages)


def test_unsupported_condition_operator_and_key_are_rejected():
    document = minimal_document()
    statement = document["policies"][0]["statements"][0]
    statement["conditions"] = {"NumericLessThan": {"aws:SourceIp": "10.0.0.0/8"}}
    assert any("Unsupported condition operator" in item for item in rejection_messages(encode_document(document)))
    statement["conditions"] = {"StringEquals": {"aws:UserAgent": "curl"}}
    assert any("Unsupported condition key" in item for item in rejection_messages(encode_document(document)))


def test_condition_values_are_validated():
    document = minimal_document()
    statement = document["policies"][0]["statements"][0]
    statement["conditions"] = {"Bool": {"aws:MultiFactorAuthPresent": "maybe"}}
    assert any("'true' or 'false'" in item for item in rejection_messages(encode_document(document)))
    statement["conditions"] = {"IpAddress": {"aws:SourceIp": "not-an-ip"}}
    assert any("not a valid IP" in item for item in rejection_messages(encode_document(document)))


def test_string_instead_of_boolean_is_rejected():
    document = minimal_document()
    document["resources"][0]["sensitive"] = "true"
    messages = rejection_messages(encode_document(document))
    assert any("valid boolean" in item for item in messages)


def test_invalid_action_and_resource_syntax_are_rejected():
    document = minimal_document()
    statement = document["policies"][0]["statements"][0]
    statement["actions"] = ["GetObject"]
    statement["resources"] = ["bucket-name"]
    messages = rejection_messages(encode_document(document))
    assert any("actions[0]" in item for item in messages)
    assert any("resources[0]" in item for item in messages)


def test_collection_size_limit_is_enforced():
    document = minimal_document()
    document["identities"] = [
        {
            "arn": f"arn:aws:iam::111122223333:user/user-{index}",
            "name": f"user-{index}",
            "type": "iam_user",
        }
        for index in range(501)
    ]
    document["policies"] = []
    messages = rejection_messages(encode_document(document))
    assert any("at most 500" in item for item in messages)


def test_invalid_json_is_rejected():
    assert any("Invalid JSON" in item for item in rejection_messages(b"{not json"))


def test_non_object_root_is_rejected():
    assert rejection_messages(b"[]")


def test_deeply_nested_json_is_rejected_without_crashing():
    assert rejection_messages(b"[" * 100_000)


def test_normalization_deduplicates_and_lowercases_effect():
    document = minimal_document()
    statement = document["policies"][0]["statements"][0]
    statement["actions"] = ["s3:GetObject", "s3:GetObject"]
    statement["conditions"] = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    normalized = process_import(encode_document(document))
    result = normalized.policies[0]["statements"][0]
    assert result["actions"] == ["s3:GetObject"]
    assert result["effect"] == "allow"
    assert result["conditions"] == {"Bool": {"aws:MultiFactorAuthPresent": ["true"]}}


def test_content_hash_is_deterministic_and_content_sensitive():
    body = encode_document(minimal_document())
    changed = minimal_document()
    changed["identities"][0]["name"] = "alice2"
    first = process_import(body).metadata["content_sha256"]
    second = process_import(body).metadata["content_sha256"]
    other = process_import(encode_document(changed)).metadata["content_sha256"]
    assert first == second
    assert first != other