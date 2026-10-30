import app.models
from app.db.base import Base


def test_expected_tables_are_registered():
    assert set(Base.metadata.tables) == {
        "users",
        "environments",
        "imports",
        "identities",
        "resources",
        "policies",
        "permission_relationships",
        "analysis_runs",
        "findings",
        "attack_paths",
    }