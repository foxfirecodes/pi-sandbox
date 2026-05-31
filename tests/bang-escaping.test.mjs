import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import test from "node:test";

import { SandboxManager } from "@carderne/sandbox-runtime";
import {
  protectBangsForSandboxWrap,
  restoreBangsAfterSandboxWrap,
} from "../index.ts";

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

async function wrapPreservingBangs(command) {
  const { protectedCommand, sentinel } = protectBangsForSandboxWrap(command);
  const wrappedCommand = await SandboxManager.wrapWithSandbox(protectedCommand, "bash");
  return restoreBangsAfterSandboxWrap(wrappedCommand, sentinel);
}

function canRunBwrap() {
  if (process.platform !== "linux") return false;
  const result = spawnSync("bwrap", ["--version"], { stdio: "ignore" });
  return result.status === 0;
}

test("bang protection replaces only bang bytes and leaves preceding backslashes for shell-quote", () => {
  const command = String.raw`node -e 'console.log(3 !== 2, "\\!, \\\\!")'`;
  const { protectedCommand, sentinel } = protectBangsForSandboxWrap(command);

  assert(!protectedCommand.includes("!"));
  assert(protectedCommand.includes(String.raw`3 ${sentinel}== 2`));
  assert(protectedCommand.includes(String.raw`"\\${sentinel}, \\\\${sentinel}"`));
  assert.equal(restoreBangsAfterSandboxWrap(protectedCommand, sentinel), command);
});

test("sandbox wrapping preserves normal and backslash-prefixed bangs", async (t) => {
  if (!canRunBwrap()) {
    t.skip("bubblewrap is not available on this platform");
    return;
  }

  const commands = [
    String.raw`node -e 'console.log(3 !== 2)'`,
    String.raw`node -e 'console.log(3 !== 2, "\\!, \\\\!")'`,
    String.raw`printf '%s\n' '\!' '\\!' '!' '!!'`,
    String.raw`printf '%s\n' 'a\!b' 'a\\!b' 'a!!!b'`,
    ...Array.from({ length: 9 }, (_value, slashCount) => {
      const slashes = "\\".repeat(slashCount);
      return `printf '%s\\n' '${slashes}!'`;
    }),
  ];

  for (const command of commands) {
    const direct = await run(command);
    assert.equal(direct.code, 0, `direct command failed: ${command}\n${direct.stderr}`);

    const wrappedCommand = await wrapPreservingBangs(command);
    const wrapped = await run(wrappedCommand);

    if (wrapped.stderr.includes("bwrap:")) {
      t.skip(`bubblewrap cannot run in this environment: ${wrapped.stderr}`);
      return;
    }

    assert.equal(wrapped.code, 0, `wrapped command failed: ${command}\n${wrapped.stderr}`);
    assert.equal(wrapped.stdout, direct.stdout, command);
  }
});
