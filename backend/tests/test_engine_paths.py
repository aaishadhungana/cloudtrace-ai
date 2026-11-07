import json

from app.engine.analyzer import analyze
from app.engine.graph import (
    PathLimits,
    assumable_roles,
    build_graph,
    identities_reaching,
    reachable_resources,
)
from app.engine.snapshot import build_snapshot
from app.ingest.pipeline import process_import
from app.models.enums import PathClassification
from app.samples.catalog import read_sample
from engine_support import (
    allow,
    bucket,
    bucket_arn,
    deny,
    document,
    external_arn,
    external_principal,
    policy,
    role,
    role_arn,
    snapshot_of,
    user,
    user_arn,
)

MFA_RAW = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
READ_SECRETS = allow(["s3:GetObject"], [f"{bucket_arn('secrets')}/*"])
SERVICE = "arn:aws:iam::111122223333:service/app-service"
SECRET = "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-password"
DATABASE = "arn:aws:rds:us-east-1:111122223333:db:orders-db"


def secrets_bucket():
    return bucket("secrets", sensitive=True)


def run(doc, limits=None):
    return analyze(snapshot_of(doc), limits)


def run_body(body: bytes):
    normalized = process_import(body)
    snapshot = build_snapshot(normalized.identities, normalized.resources, normalized.policies)
    return analyze(snapshot)


def node_arns(path):
    return (path.steps[0].source_arn, *[step.target_arn for step in path.steps])


def factor_names(path):
    return {factor.name for factor in path.assessment.factors}


def fan_out(count):
    roles = [role(f"r{index}", trusted=[user_arn("u")], policies=["p"]) for index in range(count)]
    return document([user("u"), *roles], [secrets_bucket()], [policy("p", READ_SECRETS)])


def test_two_step_chain_is_a_supported_path():
    doc = document(
        [user("u"), role("r", trusted=[user_arn("u")], policies=["p"])],
        [secrets_bucket()],
        [policy("p", READ_SECRETS)],
    )
    result = run(doc)
    assert len(result.attack_paths) == 1
    path = result.attack_paths[0]
    assert node_arns(path) == (user_arn("u"), role_arn("r"), bucket_arn("secrets"))
    assert path.classification is PathClassification.SUPPORTED
    assert path.assessment.score == 35
    assert path.summary == "u can assume r. r can read secrets."


def test_cycles_do_not_repeat_nodes_or_loop():
    doc = document(
        [
            user("u"),
            role("r1", trusted=[user_arn("u"), role_arn("r2")]),
            role("r2", trusted=[role_arn("r1")], policies=["p"]),
        ],
        [secrets_bucket()],
        [policy("p", READ_SECRETS)],
    )
    result = run(doc)
    assert {node_arns(path) for path in result.attack_paths} == {
        (user_arn("u"), role_arn("r1"), role_arn("r2"), bucket_arn("secrets")),
        (role_arn("r1"), role_arn("r2"), bucket_arn("secrets")),
    }
    for path in result.attack_paths:
        assert len(set(node_arns(path))) == len(node_arns(path))


def test_maximum_path_length_is_enforced():
    doc = document(
        [
            user("u"),
            role("r1", trusted=[user_arn("u")]),
            role("r2", trusted=[role_arn("r1")]),
            role("r3", trusted=[role_arn("r2")], policies=["p"]),
        ],
        [secrets_bucket()],
        [policy("p", READ_SECRETS)],
    )
    assert len(run(doc).attack_paths) == 3
    assert len(run(doc, PathLimits(max_length=3)).attack_paths) == 2
    assert len(run(doc, PathLimits(max_length=2)).attack_paths) == 1
    longest = run(doc).attack_paths[-1]
    assert len(longest.steps) == 4
    assert longest.assessment.score == 25


def test_explicit_deny_removes_the_path():
    blocked = deny(["s3:*"], [bucket_arn("secrets"), f"{bucket_arn('secrets')}/*"])
    doc = document(
        [user("u"), role("r", trusted=[user_arn("u")], policies=["p"])],
        [secrets_bucket()],
        [policy("p", READ_SECRETS, blocked)],
    )
    assert run(doc).attack_paths == ()


def test_untrusted_identity_has_no_path():
    doc = document(
        [user("a"), user("b"), role("r", trusted=[user_arn("a")], policies=["p"])],
        [secrets_bucket()],
        [policy("p", READ_SECRETS)],
    )
    starts = {path.start_arn for path in run(doc).attack_paths}
    assert starts == {user_arn("a")}


def test_conditional_trust_makes_the_path_potential():
    doc = document(
        [user("u"), role("r", trusted=[user_arn("u")], policies=["p"], trust_conditions=MFA_RAW)],
        [secrets_bucket()],
        [policy("p", READ_SECRETS)],
    )
    path = run(doc).attack_paths[0]
    assert path.classification is PathClassification.POTENTIAL
    assert path.assessment.score == 25
    assert "conditional_step" in factor_names(path)
    assert path.edges[0]["decision"] == "conditional"
    assert path.edges[0]["assumption"]


def test_pass_role_step_is_potential_and_explains_the_assumption():
    doc = document(
        [user("u", ["pass"]), role("r", policies=["read"])],
        [secrets_bucket()],
        [policy("pass", allow(["iam:PassRole"], [role_arn("r")])), policy("read", READ_SECRETS)],
    )
    path = run(doc).attack_paths[0]
    assert path.classification is PathClassification.POTENTIAL
    assert path.assessment.score == 25
    assert path.edges[0]["relationship"] == "can_pass_role"
    assert "service" in path.edges[0]["assumption"]
    assert "inferred_step" in factor_names(path)


def test_identity_with_direct_access_gets_no_path():
    doc = document(
        [user("u", ["read"]), role("r", trusted=[user_arn("u")], policies=["read"])],
        [secrets_bucket()],
        [policy("read", READ_SECRETS)],
    )
    assert run(doc).attack_paths == ()


def test_longer_path_through_an_identity_with_direct_access_is_skipped():
    doc = document(
        [
            user("u"),
            role("r1", trusted=[user_arn("u")], policies=["read"]),
            role("r2", trusted=[role_arn("r1")], policies=["read"]),
        ],
        [secrets_bucket()],
        [policy("read", READ_SECRETS)],
    )
    paths = run(doc).attack_paths
    assert [node_arns(path) for path in paths] == [
        (user_arn("u"), role_arn("r1"), bucket_arn("secrets"))
    ]


def test_non_sensitive_targets_are_ignored():
    doc = document(
        [user("u"), role("r", trusted=[user_arn("u")], policies=["p"])],
        [bucket("secrets", sensitive=False)],
        [policy("p", READ_SECRETS)],
    )
    assert run(doc).attack_paths == ()


def test_external_start_is_potential_and_scored_for_exposure():
    doc = document(
        [external_principal(), role("r", trusted=[external_arn()], policies=["p"])],
        [secrets_bucket()],
        [policy("p", READ_SECRETS)],
    )
    path = run(doc).attack_paths[0]
    assert path.start_arn == external_arn()
    assert path.classification is PathClassification.POTENTIAL
    assert path.assessment.score == 40
    assert {"external_start", "conditional_step"} <= factor_names(path)


def test_wildcard_trust_adds_the_public_trust_factor():
    doc = document(
        [user("u"), role("open", trusted=["*"], policies=["p"])],
        [secrets_bucket()],
        [policy("p", READ_SECRETS)],
    )
    path = run(doc).attack_paths[0]
    assert path.classification is PathClassification.SUPPORTED
    assert path.assessment.score == 55
    assert "public_trust" in factor_names(path)


def test_wildcard_terminal_grant_and_write_raise_the_score():
    doc = document(
        [user("u"), role("r", trusted=[user_arn("u")], policies=["p"])],
        [secrets_bucket()],
        [policy("p", allow(["s3:*"], ["*"]))],
    )
    path = run(doc).attack_paths[0]
    assert path.assessment.score == 65
    assert {"broad_terminal_grant", "write_capability"} <= factor_names(path)
    assert path.edges[-1]["relationship"] == "can_write"


def test_path_limits_per_pair_total_and_candidates():
    assert len(run(fan_out(2)).attack_paths) == 2
    assert run(fan_out(2)).paths_incomplete is False

    default = run(fan_out(5))
    assert len(default.attack_paths) == 3
    assert default.paths_incomplete is True

    candidate_limited = run(fan_out(5), PathLimits(max_candidates_per_pair=2, max_paths_per_pair=5))
    assert len(candidate_limited.attack_paths) == 2
    assert candidate_limited.paths_incomplete is True

    total_limited = run(fan_out(5), PathLimits(max_paths=2, max_paths_per_pair=5))
    assert len(total_limited.attack_paths) == 2
    assert total_limited.paths_incomplete is True


def test_graph_queries():
    doc = document(
        [user("u"), role("r", trusted=[user_arn("u")], policies=["p"])],
        [bucket("data")],
        [policy("p", allow(["s3:GetObject"], [f"{bucket_arn('data')}/*"]))],
    )
    snapshot = snapshot_of(doc)
    graph = build_graph(snapshot, analyze(snapshot).relationships)
    assert reachable_resources(graph, user_arn("u")) == [bucket_arn("data")]
    assert reachable_resources(graph, user_arn("u"), max_depth=1) == []
    assert identities_reaching(graph, bucket_arn("data")) == sorted(
        [user_arn("u"), role_arn("r")]
    )
    assert assumable_roles(graph, user_arn("u")) == [role_arn("r")]
    assert assumable_roles(graph, role_arn("r")) == []


def test_production_sample_paths():
    result = run_body(read_sample("acme-prod"))
    bob, deploy = user_arn("bob-developer"), role_arn("deploy-role")
    admin, runtime = role_arn("data-admin-role"), role_arn("app-runtime-role")
    customer = bucket_arn("acme-customer-data")
    actual = {
        (node_arns(path), path.classification.value, path.assessment.score)
        for path in result.attack_paths
    }
    assert len(result.attack_paths) == 9
    assert actual == {
        ((bob, deploy, customer), "supported", 65),
        ((bob, deploy, admin, SECRET), "potential", 20),
        ((bob, deploy, runtime, SECRET), "potential", 20),
        ((bob, deploy, runtime, DATABASE), "potential", 20),
        ((deploy, admin, SECRET), "potential", 25),
        ((deploy, runtime, SECRET), "potential", 25),
        ((deploy, runtime, DATABASE), "potential", 25),
        ((SERVICE, runtime, DATABASE), "supported", 35),
        ((SERVICE, runtime, SECRET), "supported", 35),
    }
    assert result.paths_incomplete is False


def test_production_sample_paths_carry_evidence_and_explained_scores():
    for path in run_body(read_sample("acme-prod")).attack_paths:
        assert len(path.evidence) == len(path.steps) == len(path.edges)
        assert all(item["statements"] for item in path.evidence)
        assert path.nodes[0]["position"] == "start"
        assert path.nodes[-1]["position"] == "target"
        assert path.nodes[-1]["is_sensitive"] is True
        total = sum(factor.points for factor in path.assessment.factors)
        assert path.assessment.score == max(0, min(100, total))


def test_attack_path_analysis_is_deterministic():
    first = run_body(read_sample("acme-prod"))
    second = run_body(read_sample("acme-prod"))
    assert first.attack_paths == second.attack_paths


def test_development_sample_has_no_paths():
    assert run_body(read_sample("acme-dev")).attack_paths == ()


def test_removing_a_trust_policy_removes_only_the_paths_that_used_it():
    before = run_body(read_sample("acme-prod"))
    document_body = json.loads(read_sample("acme-prod"))
    for identity in document_body["identities"]:
        if identity["name"] == "deploy-role":
            del identity["trust_policy"]
    after = run_body(json.dumps(document_body).encode())
    before_prints = {path.fingerprint: path for path in before.attack_paths}
    after_prints = {path.fingerprint for path in after.attack_paths}
    removed = set(before_prints) - after_prints
    assert after_prints - set(before_prints) == set()
    assert len(removed) == 4
    assert {before_prints[print_].start_arn for print_ in removed} == {user_arn("bob-developer")}