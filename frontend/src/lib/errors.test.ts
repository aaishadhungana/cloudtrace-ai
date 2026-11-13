import { describe, expect, it } from "vitest";
import { ApiError } from "@/lib/api";
import { describeError } from "@/lib/errors";

describe("describeError", () => {
  it("keeps the message and issues of an API error", () => {
    const error = new ApiError("Import validation failed", 422, [
      { path: "identities[0].arn", message: "Invalid ARN" },
    ]);
    expect(describeError(error)).toEqual({
      message: "Import validation failed",
      issues: [{ path: "identities[0].arn", message: "Invalid ARN" }],
    });
  });

  it("describes ordinary errors", () => {
    expect(describeError(new Error("boom"))).toEqual({ message: "boom", issues: [] });
  });

  it("falls back for unknown values", () => {
    expect(describeError("text")).toEqual({ message: "Something went wrong", issues: [] });
  });
});