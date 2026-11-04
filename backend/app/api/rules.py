from fastapi import APIRouter, Depends

from app.api.deps import get_current_user
from app.engine.rules.registry import RULES
from app.schemas.analysis import RuleRead

router = APIRouter(prefix="/rules", tags=["rules"], dependencies=[Depends(get_current_user)])


@router.get("", response_model=list[RuleRead])
def read_rules() -> list[RuleRead]:
    return [
        RuleRead(
            rule_id=rule.info.rule_id,
            title=rule.info.title,
            description=rule.info.description,
            finding_type=rule.info.finding_type,
        )
        for rule in RULES
    ]