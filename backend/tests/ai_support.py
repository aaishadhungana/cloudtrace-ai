from typing import Any

from app.ai.analyst import Analyst
from app.ai.gemini import get_analyst
from app.ai.schemas import (
    AttackPathAnalysisOutput,
    FindingAnalysisOutput,
    PriorityItem,
    RemediationStep,
    SecuritySummaryOutput,
    StepExplanation,
)
from app.main import app
from app.samples.catalog import read_sample
from support import API, create_environment, post_import


def remediation_step() -> RemediationStep:
    return RemediationStep(
        action="Replace the wildcard action with the specific actions the identity needs.",
        rationale="A narrower grant limits what a compromised identity can reach.",
        verify_before_applying="Confirm the identity's workflows still work with the narrower policy.",
    )


def finding_output() -> FindingAnalysisOutput:
    return FindingAnalysisOutput(
        what_was_detected="The identity is allowed every action on all resources.",
        why_it_is_risky="Full administrative access exposes everything the identity can reach.",
        potential_impact="A compromised identity could read or change any modeled resource.",
        evidence_established=["A policy statement allows * on *."],
        remaining_uncertainty=["Whether the identity is used in practice is not known."],
        remediation=[remediation_step()],
    )


def path_output(step_count: int) -> AttackPathAnalysisOutput:
    return AttackPathAnalysisOutput(
        overview="The starting identity can reach a sensitive resource through role assumption.",
        steps=[
            StepExplanation(step=number, explanation=f"Step {number} is allowed by a statement.")
            for number in range(1, step_count + 1)
        ],
        potential_impact="Access to the sensitive resource.",
        why_it_deserves_attention="Every step is allowed by the modeled permissions.",
        verify_before_claiming_exploitability=["Confirm the trust policy matches reality."],
        remediation=[remediation_step()],
    )


def summary_output() -> SecuritySummaryOutput:
    return SecuritySummaryOutput(
        overview="The environment has one critical finding and several attack paths.",
        priorities=[
            PriorityItem(
                title="Administrative wildcard",
                why="It carries the highest score.",
                recommended_action="Narrow the policy to the actions required.",
            )
        ],
        caveats=["Conditions are not evaluated."],
    )


class FakeAnalyst(Analyst):
    def __init__(
        self,
        configured: bool = True,
        error: Exception | None = None,
        path_steps: int | None = None,
        model: str = "test-model",
    ) -> None:
        self.configured = configured
        self.error = error
        self.path_steps = path_steps
        self.model = model
        self.calls: list[tuple[str, dict[str, Any], type]] = []

    @property
    def model_name(self) -> str:
        return self.model

    @property
    def is_configured(self) -> bool:
        return self.configured

    def generate(self, system_instruction, payload, schema):
        self.calls.append((system_instruction, payload, schema))
        if self.error is not None:
            raise self.error
        if schema is FindingAnalysisOutput:
            return finding_output()
        if schema is AttackPathAnalysisOutput:
            steps = self.path_steps if self.path_steps is not None else len(payload["attack_path"]["steps"])
            return path_output(steps)
        return summary_output()


def use_analyst(analyst: Analyst) -> Analyst:
    app.dependency_overrides[get_analyst] = lambda: analyst
    return analyst


def runs_url(environment_id: str) -> str:
    return f"{API}/environments/{environment_id}/analysis-runs"


def ai_url(environment_id: str, run_id: str, suffix: str) -> str:
    return f"{runs_url(environment_id)}/{run_id}/ai/{suffix}"


def analyzed(client, headers, name: str = "prod", sample: str = "acme-prod"):
    environment = create_environment(client, headers, name)
    imported = post_import(client, headers, environment["id"], read_sample(sample), f"{sample}.json")
    assert imported.status_code == 201
    run = client.post(runs_url(environment["id"]), headers=headers)
    assert run.status_code == 201
    return environment, run.json()


def critical_finding_id(client, headers, environment_id: str, run_id: str) -> str:
    response = client.get(
        f"{runs_url(environment_id)}/{run_id}/findings?severity=critical", headers=headers
    )
    assert response.status_code == 200
    return response.json()["items"][0]["id"]


def top_path_id(client, headers, environment_id: str, run_id: str) -> str:
    response = client.get(f"{runs_url(environment_id)}/{run_id}/attack-paths", headers=headers)
    assert response.status_code == 200
    return response.json()["items"][0]["id"]