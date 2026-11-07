from app.engine.scoring import RiskAssessment, RiskFactor, severity_for

SENSITIVE_TARGET_POINTS = 25
BROAD_TERMINAL_GRANT_POINTS = 20
WRITE_POINTS = 10
EXTERNAL_START_POINTS = 15
PUBLIC_TRUST_POINTS = 20
CONDITIONAL_STEP_POINTS = -10
INFERRED_STEP_POINTS = -10
SHORT_PATH_POINTS = {2: 10, 3: 5}


def assess_path(
    *,
    length: int,
    broad_terminal: bool,
    writes: bool,
    external_start: bool,
    public_trust: bool,
    conditional: bool,
    inferred: bool,
) -> RiskAssessment:
    factors = [
        RiskFactor(
            "sensitive_target", SENSITIVE_TARGET_POINTS, "The path ends at a resource marked sensitive"
        )
    ]
    if broad_terminal:
        factors.append(
            RiskFactor(
                "broad_terminal_grant",
                BROAD_TERMINAL_GRANT_POINTS,
                "The final access comes from a wildcard or broad resource grant",
            )
        )
    if writes:
        factors.append(
            RiskFactor(
                "write_capability",
                WRITE_POINTS,
                "The final step allows writing to the resource or changing its policy",
            )
        )
    short_path_points = SHORT_PATH_POINTS.get(length, 0)
    if short_path_points:
        factors.append(
            RiskFactor("short_path", short_path_points, f"The path needs only {length} steps")
        )
    if external_start:
        factors.append(
            RiskFactor(
                "external_start",
                EXTERNAL_START_POINTS,
                "The starting identity is outside the modeled account",
            )
        )
    if public_trust:
        factors.append(
            RiskFactor(
                "public_trust", PUBLIC_TRUST_POINTS, "A role on the path can be assumed by any principal"
            )
        )
    if conditional:
        factors.append(
            RiskFactor(
                "conditional_step",
                CONDITIONAL_STEP_POINTS,
                "At least one step depends on conditions that cannot be evaluated here",
            )
        )
    if inferred:
        factors.append(
            RiskFactor(
                "inferred_step",
                INFERRED_STEP_POINTS,
                "At least one step relies on an unverified assumption about starting a service",
            )
        )
    raw_score = sum(factor.points for factor in factors)
    score = max(0, min(100, raw_score))
    return RiskAssessment(
        score=score, raw_score=raw_score, severity=severity_for(score), factors=tuple(factors)
    )