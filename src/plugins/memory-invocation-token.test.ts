import { describe, expect, it } from "vitest";
import {
  createMemoryInvocationToken,
  getCurrentMemoryInvocationToken,
  isActiveMemoryInvocationToken,
  isMemoryInvocationEnforced,
  withMemoryInvocationToken,
} from "./memory-invocation-token.js";
import { memoryInvocationTokenTesting } from "./memory-invocation-token.test-support.js";

describe("memory invocation tokens", () => {
  it("treats explicit forged and missing tokens as enforced inside an active invocation", async () => {
    const token = createMemoryInvocationToken();

    await withMemoryInvocationToken(token, async () => {
      expect(isMemoryInvocationEnforced()).toBe(true);
      expect(isMemoryInvocationEnforced(undefined)).toBe(true);
      expect(isMemoryInvocationEnforced({ version: 1 })).toBe(true);
      expect(isActiveMemoryInvocationToken({ version: 1 })).toBe(false);
    });

    expect(isMemoryInvocationEnforced()).toBe(false);
    expect(isMemoryInvocationEnforced(undefined)).toBe(false);
  });

  it("binds one token for all async descendants and revokes retained descendants", async () => {
    const token = createMemoryInvocationToken();
    let releaseDescendant!: () => void;
    const descendantGate = new Promise<void>((resolve) => {
      releaseDescendant = resolve;
    });
    let retainedDescendant!: Promise<{
      current: typeof token | undefined;
      active: boolean;
      enforced: boolean;
    }>;

    await withMemoryInvocationToken(token, async () => {
      expect(getCurrentMemoryInvocationToken()).toBe(token);
      expect(isActiveMemoryInvocationToken(token)).toBe(true);
      retainedDescendant = (async () => {
        await descendantGate;
        return {
          current: getCurrentMemoryInvocationToken(),
          active: isActiveMemoryInvocationToken(token),
          enforced: isMemoryInvocationEnforced(),
        };
      })();
    });

    expect(memoryInvocationTokenTesting.readState(token)).toBe("revoked");
    releaseDescendant();
    await expect(retainedDescendant).resolves.toEqual({
      current: token,
      active: false,
      enforced: true,
    });
  });

  it("rejects token reuse and nested rebinding", async () => {
    const token = createMemoryInvocationToken();
    const nested = createMemoryInvocationToken();

    await withMemoryInvocationToken(token, async () => {
      await expect(withMemoryInvocationToken(token, async () => undefined)).rejects.toThrow(
        "memory invocation is unavailable",
      );
      await expect(withMemoryInvocationToken(nested, async () => undefined)).rejects.toThrow(
        "memory invocation is unavailable",
      );
      expect(isActiveMemoryInvocationToken(token)).toBe(true);
    });

    await expect(withMemoryInvocationToken(token, async () => undefined)).rejects.toThrow(
      "memory invocation is unavailable",
    );
    await expect(withMemoryInvocationToken(nested, async () => undefined)).resolves.toBeUndefined();
    expect(memoryInvocationTokenTesting.readState(nested)).toBe("revoked");
  });
});
