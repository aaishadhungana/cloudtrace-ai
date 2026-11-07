from dataclasses import dataclass

from app.engine.context import AnalysisContext
from app.engine.evaluation import EffectiveRelationship, compute_relationships
from app.engine.graph import PathLimits, build_graph
from app.engine.models import Snapshot
from app.engine.path_models import AttackPathDraft
from app.engine.paths import discover_paths
from app.engine.rules.base import FindingDraft
from app.engine.rules.registry import RULES

ANALYSIS_VERSION = "1.1.0"

LIMITATIONS: tuple[str, ...] = (
    "Only the documented IAM subset is evaluated. Permission boundaries, service control policies, "
    "session policies and inline policies are not modeled.",
    "Conditions are never evaluated against request context. Statements with conditions produce "
    "conditional results, not definite ones.",
    "Permissions held in external accounts are not modeled, so cross-account access is reported as "
    "conditional unless a resource policy grants it publicly.",
    "Resources of type 'other' and actions outside the built-in action catalog are not evaluated.",
    "A finding means a risky configuration exists in the imported data. It does not prove that an "
    "attacker can exploit it.",
    "Attack-path discovery follows role assumption and iam:PassRole toward resources marked "
    "sensitive. Policy modification, administrative-role targets, session chaining and the ability "
    "to start services are not modeled, so a missing path does not prove a resource is safe.",
    "An attack path is 'supported' when every step is allowed by modeled permissions and "
    "'potential' when a step depends on conditions or on an unverified assumption. Neither "
    "classification proves that an attacker can exploit the path.",
)


@dataclass(frozen=True)
class AnalysisResult:
    findings: tuple[FindingDraft, ...]
    relationships: tuple[EffectiveRelationship, ...]
    attack_paths: tuple[AttackPathDraft, ...]
    paths_incomplete: bool
    limitations: tuple[str, ...]
    analysis_version: str


def analyze(snapshot: Snapshot, limits: PathLimits | None = None) -> AnalysisResult:
    relationships = compute_relationships(snapshot)
    context = AnalysisContext(snapshot, relationships)
    collected: dict[str, FindingDraft] = {}
    for rule in RULES:
        for draft in rule.detect(context):
            collected.setdefault(draft.fingerprint, draft)
    findings = sorted(
        collected.values(),
        key=lambda draft: (-draft.assessment.score, draft.rule_id, draft.fingerprint),
    )
    graph = build_graph(snapshot, relationships)
    discovery = discover_paths(snapshot, graph, limits or PathLimits())
    return AnalysisResult(
        findings=tuple(findings),
        relationships=tuple(relationships),
        attack_paths=discovery.paths,
        paths_incomplete=discovery.incomplete,
        limitations=LIMITATIONS,
        analysis_version=ANALYSIS_VERSION,
    )