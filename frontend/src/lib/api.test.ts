import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, createImport, getMe, login, setUnauthorizedHandler } from "@/lib/api";
import { clearToken, writeToken } from "@/lib/token-store";

const fetchMock = vi.fn();

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function failure(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ApiError) {
      return error;
    }
    throw error;
  }
  throw new Error("Expected the request to fail");
}

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  clearToken();
  setUnauthorizedHandler(null);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("api client", () => {
  it("sends the stored token to authenticated endpoints", async () => {
    writeToken("token-123");
    fetchMock.mockResolvedValue(jsonResponse(200, { id: "1", email: "a@b.co", created_at: "x" }));
    await getMe();
    const init = fetchMock.mock.calls[0][1] as { headers: Record<string, string> };
    expect(init.headers.Authorization).toBe("Bearer token-123");
  });

  it("does not send the token to login", async () => {
    writeToken("token-123");
    fetchMock.mockResolvedValue(
      jsonResponse(200, { access_token: "t", token_type: "bearer", expires_in: 1800 }),
    );
    await login("a@b.co", "a-long-password");
    const init = fetchMock.mock.calls[0][1] as { headers: Record<string, string> };
    expect(init.headers.Authorization).toBeUndefined();
  });

  it("signs out on 401 for authenticated requests only", async () => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    fetchMock.mockResolvedValue(jsonResponse(401, { detail: "Not authenticated" }));
    const error = await failure(getMe());
    expect(error.status).toBe(401);
    expect(handler).toHaveBeenCalledTimes(1);

    fetchMock.mockResolvedValue(jsonResponse(401, { detail: "Invalid email or password" }));
    await failure(login("a@b.co", "wrong-password"));
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("turns import validation issues into API error issues", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(422, {
        detail: {
          message: "Import validation failed",
          issues: [{ path: "policies[0].id", message: "Duplicate id" }],
        },
      }),
    );
    const error = await failure(createImport("env", "{}", "file.json"));
    expect(error.message).toBe("Import validation failed");
    expect(error.issues).toEqual([{ path: "policies[0].id", message: "Duplicate id" }]);
  });

  it("turns request validation arrays into issues", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(422, { detail: [{ loc: ["body", "password"], msg: "Too short", type: "x" }] }),
    );
    const error = await failure(login("a@b.co", "x"));
    expect(error.issues).toEqual([{ path: "password", message: "Too short" }]);
  });

  it("reports network failures without leaking details", async () => {
    fetchMock.mockRejectedValue(new TypeError("fetch failed"));
    const error = await failure(getMe());
    expect(error.status).toBe(0);
    expect(error.message).toBe("Cannot reach the server");
  });
});