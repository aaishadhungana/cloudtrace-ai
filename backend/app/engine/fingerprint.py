import hashlib
import json

from app.engine.models import PrincipalStatement, Statement


def make_fingerprint(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def statement_digest(statement: Statement | PrincipalStatement) -> str:
    subjects = (
        statement.resources if isinstance(statement, Statement) else statement.principals
    )
    canonical = json.dumps(
        {
            "effect": statement.effect,
            "actions": sorted(statement.actions),
            "subjects": sorted(subjects),
            "conditions": statement.conditions,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]