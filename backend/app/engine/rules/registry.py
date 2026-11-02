from app.engine.rules.base import Rule
from app.engine.rules.escalation import (
    PASS_ROLE_INFO,
    POLICY_MODIFICATION_INFO,
    detect_pass_role_wildcard,
    detect_policy_modification,
)
from app.engine.rules.resource_policies import (
    CROSS_ACCOUNT_RESOURCE_INFO,
    PUBLIC_RESOURCE_INFO,
    detect_cross_account_resource_grant,
    detect_public_resource,
)
from app.engine.rules.sensitive import (
    BROAD_SENSITIVE_INFO,
    DENY_DEPENDENCY_INFO,
    detect_broad_sensitive_access,
    detect_deny_dependency,
)
from app.engine.rules.trust import (
    CROSS_ACCOUNT_TRUST_INFO,
    TRUST_ANY_INFO,
    detect_cross_account_trust,
    detect_trust_any_principal,
)
from app.engine.rules.wildcards import (
    ADMIN_INFO,
    SERVICE_INFO,
    detect_admin_wildcard,
    detect_service_wildcard,
)

RULES: tuple[Rule, ...] = (
    Rule(ADMIN_INFO, detect_admin_wildcard),
    Rule(SERVICE_INFO, detect_service_wildcard),
    Rule(BROAD_SENSITIVE_INFO, detect_broad_sensitive_access),
    Rule(TRUST_ANY_INFO, detect_trust_any_principal),
    Rule(CROSS_ACCOUNT_TRUST_INFO, detect_cross_account_trust),
    Rule(POLICY_MODIFICATION_INFO, detect_policy_modification),
    Rule(PASS_ROLE_INFO, detect_pass_role_wildcard),
    Rule(PUBLIC_RESOURCE_INFO, detect_public_resource),
    Rule(CROSS_ACCOUNT_RESOURCE_INFO, detect_cross_account_resource_grant),
    Rule(DENY_DEPENDENCY_INFO, detect_deny_dependency),
)