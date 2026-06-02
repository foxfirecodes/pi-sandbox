import test from "node:test";

import assert from "node:assert/strict";

import {
  commandMatchesPattern,
  findMatchingAllowCommandPattern,
  findMatchingDenyCommandPattern,
  splitCommandForPatternMatching,
} from "../index.ts";

test("plain command patterns are exact matches", () => {
  assert.equal(commandMatchesPattern("git commit", "git commit"), true);
  assert.equal(commandMatchesPattern("git commit && echo ok", "git commit"), false);
});

test("glob command patterns still match the whole command", () => {
  assert.equal(commandMatchesPattern("git commit -m ok", "git commit*"), true);
  assert.equal(commandMatchesPattern("git commit -m ok && echo ok", "git commit*"), true);
});

test("command splitting honors quotes and escapes", () => {
  assert.deepEqual(splitCommandForPatternMatching("echo 'a;b' && printf \"x;y\"").segments, [
    "echo 'a;b'",
    'printf "x;y"',
  ]);
  assert.deepEqual(splitCommandForPatternMatching(String.raw`echo a\;b; echo c`).segments, [
    String.raw`echo a\;b`,
    "echo c",
  ]);
});

test("allow command patterns must match every chained command segment", () => {
  assert.equal(findMatchingAllowCommandPattern("git commit -m ok", ["git commit*"]), "git commit*");
  assert.equal(
    findMatchingAllowCommandPattern("git commit -m ok && echo ok", ["git commit*"]),
    undefined,
  );
  assert.equal(
    findMatchingAllowCommandPattern("git commit -m ok && echo ok", ["git commit*", "echo ok"]),
    "git commit*",
  );
});

test("allow command patterns do not approve malformed empty segments", () => {
  assert.equal(findMatchingAllowCommandPattern("git commit -m ok &&", ["git commit*"]), undefined);
  assert.equal(
    findMatchingAllowCommandPattern("git commit -m ok;;echo ok", ["git commit*", "echo ok"]),
    undefined,
  );
});

test("deny command patterns match individual chained command segments", () => {
  assert.equal(
    findMatchingDenyCommandPattern("echo ok && git commit", ["git commit"]),
    "git commit",
  );
  assert.equal(
    findMatchingDenyCommandPattern("echo ok; git commit -m ok", ["git commit*"]),
    "git commit*",
  );
});
