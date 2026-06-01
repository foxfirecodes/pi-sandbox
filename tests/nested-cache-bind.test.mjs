import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { SandboxManager } from "@foxfirecodes/sandbox-runtime";
import assert from "node:assert/strict";

function canRunBwrap() {
  if (process.platform !== "linux") return false;
  const result = spawnSync("bwrap", ["--version"], { stdio: "ignore" });
  return result.status === 0;
}

function run(command) {
  return new Promise((resolve) => {
    const child = spawn("bash", ["-c", command], {
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (data) => {
      stdout += data;
    });
    child.stderr.on("data", (data) => {
      stderr += data;
    });
    child.on("close", (code) => {
      resolve({ code, stdout, stderr });
    });
  });
}

test("broad cache read allowance does not shadow nested writable cache paths on Linux", async (t) => {
  if (!canRunBwrap()) {
    t.skip("bubblewrap is not available on this platform");
    return;
  }

  const home = homedir();
  const cachePath = join(home, ".cache");
  const uvCachePath = join(cachePath, "uv");
  const target = join(uvCachePath, `pi-sandbox-nested-bind-${process.pid}`);
  const targetFile = join(target, "sdists-v9", ".git", "objects", "test");

  mkdirSync(uvCachePath, { recursive: true });
  rmSync(target, { recursive: true, force: true });

  const filesystem = {
    denyRead: ["/home"],
    allowRead: ["~/.cache"],
    allowWrite: ["~/.cache/uv"],
    denyWrite: [],
  };

  try {
    const command = `mkdir -p ${target}/sdists-v9/.git/objects && printf ok > ${targetFile} && cat ${targetFile}`;
    const wrappedCommand = await SandboxManager.wrapWithSandbox(command, "bash", {
      filesystem,
    });

    const readOnlyCacheBind = `--ro-bind ${cachePath} ${cachePath}`;
    const writableUvBind = `--bind ${uvCachePath} ${uvCachePath}`;
    assert.notEqual(
      wrappedCommand.indexOf(readOnlyCacheBind),
      -1,
      "expected broad cache read-only bind in wrapped command",
    );
    assert(
      wrappedCommand.lastIndexOf(writableUvBind) > wrappedCommand.indexOf(readOnlyCacheBind),
      "nested writable cache bind should be restored after the broad read-only cache bind",
    );

    const wrapped = await run(wrappedCommand);
    if (wrapped.stderr.includes("bwrap:")) {
      t.skip(`bubblewrap cannot run in this environment: ${wrapped.stderr}`);
      return;
    }

    assert.equal(wrapped.code, 0, wrapped.stderr);
    assert.equal(wrapped.stdout, "ok");
  } finally {
    rmSync(target, { recursive: true, force: true });
    await SandboxManager.reset();
  }
});
