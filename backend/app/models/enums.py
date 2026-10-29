from enum import StrEnum


class CloudProvider(StrEnum):
    AWS = "aws"


class ValidationStatus(StrEnum):
    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"


class IdentityType(StrEnum):
    IAM_USER = "iam_user"
    IAM_ROLE = "iam_role"
    SERVICE = "service"
    EXTERNAL_PRINCIPAL = "external_principal"


class ResourceType(StrEnum):
    STORAGE_BUCKET = "storage_bucket"
    COMPUTE = "compute"
    SECRET = "secret"
    DATABASE = "database"
    OTHER = "other"


class RelationshipType(StrEnum):
    CAN_ASSUME = "can_assume"
    CAN_READ = "can_read"
    CAN_WRITE = "can_write"
    CAN_MODIFY_POLICY = "can_modify_policy"
    CAN_PASS_ROLE = "can_pass_role"
    ACCESSIBLE_TO_PRINCIPAL = "accessible_to_principal"


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class AnalysisStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class PathClassification(StrEnum):
    SUPPORTED = "supported"
    POTENTIAL = "potential"