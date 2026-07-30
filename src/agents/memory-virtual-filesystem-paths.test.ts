import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { isRawControlledMemoryWorkspacePath } from "./memory-virtual-filesystem-paths.js";

const tempDirs: string[] = [];

function makeWorkspace(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-memory-vfs-"));
  tempDirs.push(root);
  return root;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("isRawControlledMemoryWorkspacePath", () => {
  it("rejects direct controlled paths across case and Unicode normalization variants", async () => {
    const root = makeWorkspace();

    await expect(isRawControlledMemoryWorkspacePath({ root, pathname: "MEMORY.md" })).resolves.toBe(
      true,
    );
    await expect(
      isRawControlledMemoryWorkspacePath({ root, pathname: "ｍｅｍｏｒｙ.md" }),
    ).resolves.toBe(true);
    await expect(
      isRawControlledMemoryWorkspacePath({ root, pathname: "memory/private.md" }),
    ).resolves.toBe(true);
    await expect(
      isRawControlledMemoryWorkspacePath({ root, pathname: "notes/memory.md" }),
    ).resolves.toBe(false);
  });

  it("maps container and file-URL paths before applying the raw-path policy", async () => {
    const root = makeWorkspace();

    await expect(
      isRawControlledMemoryWorkspacePath({
        root,
        pathname: "/workspace/MEMORY.md",
        containerWorkdir: "/workspace",
      }),
    ).resolves.toBe(true);
    await expect(
      isRawControlledMemoryWorkspacePath({
        root,
        pathname: "file:///workspace/USER.md",
        containerWorkdir: "/workspace",
      }),
    ).resolves.toBe(true);
    await expect(
      isRawControlledMemoryWorkspacePath({
        root,
        pathname: "file:///workspace/%2FMEMORY.md",
        containerWorkdir: "/workspace",
      }),
    ).resolves.toBe(false);
  });

  it.runIf(process.platform !== "win32")(
    "rejects symlink and hard-link aliases to controlled memory files",
    async () => {
      const root = makeWorkspace();
      fs.writeFileSync(path.join(root, "MEMORY.md"), "private");
      fs.symlinkSync("MEMORY.md", path.join(root, "memory-alias"));
      fs.linkSync(path.join(root, "MEMORY.md"), path.join(root, "memory-hard-link"));

      await expect(
        isRawControlledMemoryWorkspacePath({ root, pathname: "memory-alias" }),
      ).resolves.toBe(true);
      await expect(
        isRawControlledMemoryWorkspacePath({ root, pathname: "memory-hard-link" }),
      ).resolves.toBe(true);
    },
  );
});
