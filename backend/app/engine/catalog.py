from dataclasses import dataclass

from app.models.enums import IdentityType, RelationshipType, ResourceType

OBJECTS = "/*"

WRITE_TYPES = frozenset({RelationshipType.CAN_WRITE, RelationshipType.CAN_MODIFY_POLICY})


@dataclass(frozen=True)
class ActionSpec:
    action: str
    target_suffix: str = ""


RESOURCE_CATALOG: dict[ResourceType, dict[RelationshipType, tuple[ActionSpec, ...]]] = {
    ResourceType.STORAGE_BUCKET: {
        RelationshipType.CAN_READ: (
            ActionSpec("s3:GetObject", OBJECTS),
            ActionSpec("s3:ListBucket"),
        ),
        RelationshipType.CAN_WRITE: (
            ActionSpec("s3:PutObject", OBJECTS),
            ActionSpec("s3:DeleteObject", OBJECTS),
        ),
        RelationshipType.CAN_MODIFY_POLICY: (
            ActionSpec("s3:PutBucketPolicy"),
            ActionSpec("s3:PutBucketAcl"),
        ),
    },
    ResourceType.SECRET: {
        RelationshipType.CAN_READ: (ActionSpec("secretsmanager:GetSecretValue"),),
        RelationshipType.CAN_WRITE: (
            ActionSpec("secretsmanager:PutSecretValue"),
            ActionSpec("secretsmanager:DeleteSecret"),
        ),
        RelationshipType.CAN_MODIFY_POLICY: (ActionSpec("secretsmanager:PutResourcePolicy"),),
    },
    ResourceType.DATABASE: {
        RelationshipType.CAN_READ: (ActionSpec("rds-db:connect"),),
        RelationshipType.CAN_WRITE: (
            ActionSpec("rds:ModifyDBInstance"),
            ActionSpec("rds:DeleteDBInstance"),
        ),
    },
    ResourceType.COMPUTE: {
        RelationshipType.CAN_READ: (ActionSpec("ec2:DescribeInstances"),),
        RelationshipType.CAN_WRITE: (
            ActionSpec("ec2:StartInstances"),
            ActionSpec("ec2:StopInstances"),
            ActionSpec("ec2:TerminateInstances"),
            ActionSpec("ssm:SendCommand"),
        ),
    },
}

IDENTITY_CATALOG: dict[IdentityType, dict[RelationshipType, tuple[ActionSpec, ...]]] = {
    IdentityType.IAM_ROLE: {
        RelationshipType.CAN_ASSUME: (ActionSpec("sts:AssumeRole"),),
        RelationshipType.CAN_PASS_ROLE: (ActionSpec("iam:PassRole"),),
        RelationshipType.CAN_MODIFY_POLICY: (
            ActionSpec("iam:PutRolePolicy"),
            ActionSpec("iam:AttachRolePolicy"),
            ActionSpec("iam:UpdateAssumeRolePolicy"),
        ),
    },
    IdentityType.IAM_USER: {
        RelationshipType.CAN_MODIFY_POLICY: (
            ActionSpec("iam:PutUserPolicy"),
            ActionSpec("iam:AttachUserPolicy"),
        ),
    },
}