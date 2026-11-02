import pytest

from app.engine.scoring import Capability, Exposure, assess, severity_for
from app.models.enums import Severity


def test_admin_with_sensitive_reach_and_write_is_critical():
    result = assess(Capability.ADMIN_WILDCARD, reaches_sensitive=True, can_write=True)
    assert result.score == 80
    assert result.severity is Severity.CRITICAL
    assert [factor.name for factor in result.factors] == [
        "capability",
        "sensitive_target",
        "write_capability",
    ]


def test_conditions_reduce_the_score_by_ten():
    plain = assess(Capability.ADMIN_WILDCARD, reaches_sensitive=True, can_write=True)
    conditional = assess(
        Capability.ADMIN_WILDCARD, reaches_sensitive=True, can_write=True, conditional=True
    )
    assert conditional.score == plain.score - 10
    assert conditional.severity is Severity.HIGH
    assert "condition_restriction" in [factor.name for factor in conditional.factors]


def test_score_is_clamped_but_raw_score_is_kept():
    result = assess(
        Capability.PUBLIC_WRITE,
        exposure=Exposure.PUBLIC,
        reaches_sensitive=True,
        can_write=True,
        role_chain=True,
    )
    assert result.raw_score == 105
    assert result.score == 100


def test_factor_points_add_up_to_the_raw_score():
    result = assess(
        Capability.CROSS_ACCOUNT_TRUST,
        exposure=Exposure.EXTERNAL,
        reaches_sensitive=True,
        role_chain=True,
        conditional=True,
    )
    assert sum(factor.points for factor in result.factors) == result.raw_score == 60


def test_score_never_goes_below_zero():
    assert assess(Capability.DENY_DEPENDENCY, conditional=True).score == 0


@pytest.mark.parametrize(
    ("score", "severity"),
    [
        (0, Severity.INFO),
        (19, Severity.INFO),
        (20, Severity.LOW),
        (39, Severity.LOW),
        (40, Severity.MEDIUM),
        (59, Severity.MEDIUM),
        (60, Severity.HIGH),
        (79, Severity.HIGH),
        (80, Severity.CRITICAL),
        (100, Severity.CRITICAL),
    ],
)
def test_severity_bands(score, severity):
    assert severity_for(score) is severity


def test_assessment_is_deterministic():
    first = assess(Capability.PASS_ROLE_WILDCARD, reaches_sensitive=True, role_chain=True)
    second = assess(Capability.PASS_ROLE_WILDCARD, reaches_sensitive=True, role_chain=True)
    assert first == second
    assert first.factor_dicts() == second.factor_dicts()