import { readToken } from "@/lib/token-store";
import type {
  Environment,
  EnvironmentCreate,
  HealthResponse,
  ImportIssue,
  ImportRecord,
  Sample,
  TokenResponse,
  User,
} from "@/lib/types";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api/v1";

export class ApiError extends Error {
  readonly status: number;
  readonly issues: ImportIssue[];

  constructor(message: string, status: number, issues: ImportIssue[] = []) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.issues = issues;
  }
}

let unauthorizedHandler: (() => void) | null = null;

export function setUnauthorizedHandler(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
}

interface SendOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  json?: unknown;
  rawBody?: string;
  query?: Record<string, string>;
  authenticated?: boolean;
  signal?: AbortSignal;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readIssues(value: unknown, pathKey: string, messageKey: string): ImportIssue[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter(isRecord).map((item) => {
    const rawPath = item[pathKey];
    const rawMessage = item[messageKey];
    let path = "";
    if (Array.isArray(rawPath)) {
      path = rawPath.filter((part) => part !== "body").join(".");
    } else if (typeof rawPath === "string") {
      path = rawPath;
    }
    return {
      path,
      message: typeof rawMessage === "string" ? rawMessage : "Invalid value",
    };
  });
}

async function toApiError(response: Response): Promise<ApiError> {
  const fallback = `Request failed with status ${response.status}`;
  const payload: unknown = await response.json().catch(() => null);
  if (!isRecord(payload)) {
    return new ApiError(fallback, response.status);
  }
  const detail = payload.detail;
  if (typeof detail === "string") {
    return new ApiError(detail, response.status);
  }
  if (Array.isArray(detail)) {
    return new ApiError(
      "Request validation failed",
      response.status,
      readIssues(detail, "loc", "msg"),
    );
  }
  if (isRecord(detail)) {
    const message = typeof detail.message === "string" ? detail.message : fallback;
    return new ApiError(message, response.status, readIssues(detail.issues, "path", "message"));
  }
  return new ApiError(fallback, response.status);
}

async function send(path: string, options: SendOptions = {}): Promise<Response> {
  const { method = "GET", json, rawBody, query, authenticated = true, signal } = options;
  const headers: Record<string, string> = { Accept: "application/json" };
  if (authenticated) {
    const token = readToken();
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
  }
  const body = json !== undefined ? JSON.stringify(json) : rawBody;
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  const search = query ? `?${new URLSearchParams(query).toString()}` : "";

  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}${search}`, {
      method,
      headers,
      body,
      signal,
      cache: "no-store",
    });
  } catch (error) {
    if (signal?.aborted) {
      throw error;
    }
    throw new ApiError("Cannot reach the server", 0);
  }

  if (response.status === 401 && authenticated && unauthorizedHandler) {
    unauthorizedHandler();
  }
  if (!response.ok) {
    throw await toApiError(response);
  }
  return response;
}

async function requestJson<T>(path: string, options: SendOptions = {}): Promise<T> {
  const response = await send(path, options);
  return (await response.json()) as T;
}

function segment(value: string): string {
  return encodeURIComponent(value);
}

export function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return requestJson<HealthResponse>("/health", { signal, authenticated: false });
}

export function register(email: string, password: string): Promise<User> {
  return requestJson<User>("/auth/register", {
    method: "POST",
    json: { email, password },
    authenticated: false,
  });
}

export function login(email: string, password: string): Promise<TokenResponse> {
  return requestJson<TokenResponse>("/auth/login", {
    method: "POST",
    json: { email, password },
    authenticated: false,
  });
}

export function getMe(signal?: AbortSignal): Promise<User> {
  return requestJson<User>("/auth/me", { signal });
}

export function listEnvironments(signal?: AbortSignal): Promise<Environment[]> {
  return requestJson<Environment[]>("/environments", { signal });
}

export function getEnvironment(id: string, signal?: AbortSignal): Promise<Environment> {
  return requestJson<Environment>(`/environments/${segment(id)}`, { signal });
}

export function createEnvironment(payload: EnvironmentCreate): Promise<Environment> {
  return requestJson<Environment>("/environments", { method: "POST", json: payload });
}

export async function deleteEnvironment(id: string): Promise<void> {
  await send(`/environments/${segment(id)}`, { method: "DELETE" });
}

export function listImports(environmentId: string, signal?: AbortSignal): Promise<ImportRecord[]> {
  return requestJson<ImportRecord[]>(`/environments/${segment(environmentId)}/imports`, {
    signal,
  });
}

export function createImport(
  environmentId: string,
  body: string,
  source: string,
): Promise<ImportRecord> {
  return requestJson<ImportRecord>(`/environments/${segment(environmentId)}/imports`, {
    method: "POST",
    rawBody: body,
    query: { source },
  });
}

export function listSamples(signal?: AbortSignal): Promise<Sample[]> {
  return requestJson<Sample[]>("/samples", { signal });
}

export async function getSampleDocument(name: string, signal?: AbortSignal): Promise<string> {
  const response = await send(`/samples/${segment(name)}`, { signal });
  return response.text();
}