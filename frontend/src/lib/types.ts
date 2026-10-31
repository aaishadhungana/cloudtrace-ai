export interface HealthResponse {
  status: string;
  database: string;
  version: string;
}

export interface User {
  id: string;
  email: string;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export type CloudProvider = "aws";

export interface Environment {
  id: string;
  name: string;
  cloud_provider: CloudProvider;
  description: string | null;
  created_at: string;
}

export interface EnvironmentCreate {
  name: string;
  description: string | null;
}

export type ValidationStatus = "pending" | "valid" | "invalid";

export interface ImportMetadata {
  identity_count: number;
  resource_count: number;
  policy_count: number;
  statement_count: number;
  sensitive_resource_count: number;
  content_sha256: string;
}

export interface ImportRecord {
  id: string;
  environment_id: string;
  import_source: string;
  schema_version: string;
  validation_status: ValidationStatus;
  sanitized_metadata: ImportMetadata;
  created_at: string;
}

export interface ImportIssue {
  path: string;
  message: string;
}

export interface Sample {
  name: string;
  title: string;
  description: string;
}