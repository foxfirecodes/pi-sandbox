/**
 * Based on https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/examples/extensions/sandbox/index.ts
 * by Mario Zechner, used under the MIT License.
 *
 * Sandbox Extension - OS-level sandboxing for bash commands, plus path policy
 * enforcement for pi's read/write/edit tools, with interactive permission prompts.
 *
 * Uses @foxfirecodes/sandbox-runtime to enforce filesystem and network
 * restrictions on bash commands at the OS level (sandbox-exec on macOS,
 * bubblewrap on Linux). Also intercepts the read, write, and edit tools to
 * apply the same denyRead/denyWrite/allowWrite filesystem rules, which OS-level
 * sandboxing cannot cover (those tools run directly in Node.js, not in a
 * subprocess).
 *
 * When a block is triggered, the user is prompted to:
 *   (a) Abort (keep blocked)
 *   (b) Allow for this session only  — stored in memory, agent cannot access
 *   (c) Allow for this project       — written to .pi/sandbox.json
 *   (d) Allow for all projects       — written to ~/.pi/agent/sandbox.json
 *
 * What gets prompted vs. hard-blocked:
 *   - commands: hard-blocked if they match commandPatterns.denyPatterns
 *   - commands: bypassed entirely if they match commandPatterns.allowPatterns
 *   - domains: prompted if not whitelisted nor explicitly denied
 *   - write: prompted if not whitelisted nor explicitly denied
 *   - read: always prompted (because denyRead is used for broad block, may want to punch holes)
 *
 * IMPORTANT — precedence for read:
 *   Read:  allowRead OVERRIDES denyRead (prompt grant adds to allowRead)
 *   Write: denyWrite OVERRIDES allowWrite (most-specific deny wins)
 *
 * Config files (merged, project takes precedence):
 * - ~/.pi/agent/sandbox.json (global)
 * - <cwd>/.pi/sandbox.json  (project-local)
 *
 * Example .pi/sandbox.json:
 * ```json
 * {
 *   "enabled": true,
 *   "commandPatterns": {
 *     "allowPatterns": ["gh auth status"],
 *     "denyPatterns": []
 *   },
 *   "network": {
 *     "allowedDomains": ["github.com", "*.github.com"],
 *     "deniedDomains": []
 *   },
 *   "filesystem": {
 *     "denyRead": ["/Users", "/home"],
 *     "allowRead": [".", "~/.config", "~/.local", "Library"],
 *     "allowWrite": [".", "/tmp"],
 *     "denyWrite": [".env"]
 *   }
 * }
 * ```
 *
 * Usage:
 * - `pi -e ./sandbox` - sandbox enabled with default/config settings
 * - `pi -e ./sandbox --no-sandbox` - disable sandboxing
 * - `/sandbox` - show current sandbox configuration
 *
 * Setup:
 * 1. Copy sandbox/ directory to ~/.pi/agent/extensions/
 * 2. Run `npm install` in ~/.pi/agent/extensions/sandbox/
 *
 * Linux also requires: bubblewrap, socat, ripgrep
 */

import type {
  AgentToolResult,
  ExtensionAPI,
  ExtensionContext,
} from "@earendil-works/pi-coding-agent";

import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

import {
  type BashOperations,
  createBashToolDefinition,
  getAgentDir,
  getShellConfig,
  isToolCallEventType,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";
import { matchesKey, Key, truncateToWidth } from "@earendil-works/pi-tui";
import {
  SandboxManager,
  type SandboxAskCallback,
  type SandboxRuntimeConfig,
} from "@foxfirecodes/sandbox-runtime";

interface CommandPatternsConfig {
  /**
   * Command patterns that bypass all bash sandboxing when matched.
   * Keep these narrow: a matching command runs completely unsandboxed.
   */
  allowPatterns?: string[];
  /** Command patterns that are hard-blocked before execution. */
  denyPatterns?: string[];
}

type CommandPatternDecision =
  | { action: "deny"; listName: "denyPatterns"; pattern: string }
  | { action: "allow"; listName: "allowPatterns"; pattern: string }
  | { action: "sandbox" };

interface SandboxConfig extends SandboxRuntimeConfig {
  enabled?: boolean;
  /**
   * Non-regex entries use shell-style globs matched against the whole command.
   * Entries of the form re:/pattern/flags are treated as JavaScript regexes.
   * denyPatterns take precedence over allowPatterns.
   */
  commandPatterns?: CommandPatternsConfig;
}

const DEFAULT_CONFIG: SandboxConfig = {
  enabled: true,
  commandPatterns: {
    allowPatterns: [],
    denyPatterns: [],
  },
  network: {
    allowedDomains: [
      "npmjs.org",
      "*.npmjs.org",
      "registry.npmjs.org",
      "registry.yarnpkg.com",
      "pypi.org",
      "*.pypi.org",
      "github.com",
      "*.github.com",
      "api.github.com",
      "raw.githubusercontent.com",
    ],
    deniedDomains: [],
  },
  filesystem: {
    denyRead: ["/Users", "/home"],
    allowRead: [".", "~/.config", "~/.local", "Library"],
    allowWrite: [".", "/tmp"],
    denyWrite: [".env", ".env.*", "*.pem", "*.key"],
  },
};

function loadConfig(cwd: string): SandboxConfig {
  const projectConfigPath = join(cwd, ".pi", "sandbox.json");
  const globalConfigPath = join(getAgentDir(), "sandbox.json");

  let globalConfig: Partial<SandboxConfig> = {};
  let projectConfig: Partial<SandboxConfig> = {};

  if (existsSync(globalConfigPath)) {
    try {
      globalConfig = JSON.parse(readFileSync(globalConfigPath, "utf-8"));
    } catch (e) {
      console.error(`Warning: Could not parse ${globalConfigPath}: ${e}`);
    }
  }

  if (existsSync(projectConfigPath)) {
    try {
      projectConfig = JSON.parse(readFileSync(projectConfigPath, "utf-8"));
    } catch (e) {
      console.error(`Warning: Could not parse ${projectConfigPath}: ${e}`);
    }
  }

  return deepMerge(deepMerge(DEFAULT_CONFIG, globalConfig), projectConfig);
}

function deepMerge(base: SandboxConfig, overrides: Partial<SandboxConfig>): SandboxConfig {
  const result: SandboxConfig = { ...base };

  if (overrides.enabled !== undefined) result.enabled = overrides.enabled;
  if (overrides.commandPatterns) {
    result.commandPatterns = {
      ...base.commandPatterns,
      ...overrides.commandPatterns,
    };
  }
  if (overrides.network) {
    result.network = { ...base.network, ...overrides.network };
  }
  if (overrides.filesystem) {
    result.filesystem = { ...base.filesystem, ...overrides.filesystem };
  }

  const extOverrides = overrides as {
    ignoreViolations?: Record<string, string[]>;
    enableWeakerNestedSandbox?: boolean;
    allowBrowserProcess?: boolean;
  };
  const extResult = result as {
    ignoreViolations?: Record<string, string[]>;
    enableWeakerNestedSandbox?: boolean;
    allowBrowserProcess?: boolean;
  };

  if (extOverrides.ignoreViolations) {
    extResult.ignoreViolations = extOverrides.ignoreViolations;
  }
  if (extOverrides.enableWeakerNestedSandbox !== undefined) {
    extResult.enableWeakerNestedSandbox = extOverrides.enableWeakerNestedSandbox;
  }
  if (extOverrides.allowBrowserProcess !== undefined) {
    extResult.allowBrowserProcess = extOverrides.allowBrowserProcess;
  }

  return result;
}

// ── Domain helpers ────────────────────────────────────────────────────────────

export function shouldPromptForWrite(
  path: string,
  allowWrite: string[],
  matchesPattern: (path: string, patterns: string[]) => boolean,
): boolean {
  // Secure default: empty allowWrite means deny-all writes (prompt every path).
  return allowWrite.length === 0 || !matchesPattern(path, allowWrite);
}

function extractDomainsFromCommand(command: string): string[] {
  const urlRegex = /https?:\/\/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;
  const domains = new Set<string>();
  let match;
  while ((match = urlRegex.exec(command)) !== null) {
    domains.add(match[1]);
  }
  return [...domains];
}

function domainMatchesPattern(domain: string, pattern: string): boolean {
  if (pattern === "*") return true;
  if (pattern.startsWith("*.")) {
    const base = pattern.slice(2);
    return domain === base || domain.endsWith("." + base);
  }
  return domain === pattern;
}

function allowsAllDomains(allowedDomains: string[] | undefined): boolean {
  return allowedDomains?.includes("*") ?? false;
}

function domainIsAllowed(domain: string, allowedDomains: string[]): boolean {
  return allowedDomains.some((p) => domainMatchesPattern(domain, p));
}

function createNetworkAskCallback(allowedDomains: string[]): SandboxAskCallback {
  return async ({ host }) => domainIsAllowed(host, allowedDomains);
}

// ── Command pattern helpers ───────────────────────────────────────────────────

function normalizeCommandForPattern(command: string): string {
  return command.trim();
}

function escapeRegExp(value: string): string {
  return value.replace(/[|\\{}()[\]^$+*?.]/g, "\\$&");
}

function globPatternToRegExp(pattern: string): RegExp {
  let source = "";
  for (const char of pattern) {
    if (char === "*") {
      source += "[\\s\\S]*";
    } else if (char === "?") {
      source += "[\\s\\S]";
    } else {
      source += escapeRegExp(char);
    }
  }
  return new RegExp(`^${source}$`);
}

function regexFromCommandPattern(pattern: string): RegExp | null {
  const regexPrefix = "re:";
  if (!pattern.startsWith(regexPrefix)) return null;

  const expression = pattern.slice(regexPrefix.length);
  if (!expression.startsWith("/")) return null;

  const lastSlash = expression.lastIndexOf("/");
  if (lastSlash === 0) return null;

  const source = expression.slice(1, lastSlash);
  const flags = expression.slice(lastSlash + 1);
  if (!/^[dgimsuvy]*$/.test(flags)) return null;

  try {
    return new RegExp(source, flags);
  } catch {
    return null;
  }
}

export function commandMatchesPattern(command: string, pattern: string): boolean {
  const normalizedCommand = normalizeCommandForPattern(command);
  const normalizedPattern = pattern.trim();
  if (!normalizedPattern) return false;

  const regex = regexFromCommandPattern(normalizedPattern);
  if (regex) return regex.test(normalizedCommand);

  if (normalizedPattern.includes("*") || normalizedPattern.includes("?")) {
    return globPatternToRegExp(normalizedPattern).test(normalizedCommand);
  }

  return normalizedCommand === normalizedPattern;
}

export interface CommandSegmentsForPatternMatching {
  segments: string[];
  hasSeparator: boolean;
  hasEmptySegment: boolean;
}

// This is intentionally only a lightweight shell-ish splitter, not a full parser.
// It prevents a single allowPattern match from bypassing the sandbox for a
// top-level command chain such as `git commit && other-command`.
export function splitCommandForPatternMatching(command: string): CommandSegmentsForPatternMatching {
  const segments: string[] = [];
  let current = "";
  let quote: "'" | '"' | null = null;
  let hasSeparator = false;

  const pushSegment = () => {
    segments.push(current.trim());
    current = "";
  };

  for (let i = 0; i < command.length; i++) {
    const char = command[i];

    if (quote) {
      current += char;
      if (char === quote) {
        quote = null;
      } else if (quote === '"' && char === "\\" && i + 1 < command.length) {
        current += command[++i];
      }
      continue;
    }

    if (char === "'" || char === '"') {
      quote = char;
      current += char;
      continue;
    }

    if (char === "\\" && i + 1 < command.length) {
      current += char + command[++i];
      continue;
    }

    const next = command[i + 1];
    if (char === "&" && next === "&") {
      pushSegment();
      hasSeparator = true;
      i++;
      continue;
    }
    if (char === "|" && next === "|") {
      pushSegment();
      hasSeparator = true;
      i++;
      continue;
    }
    if (char === ";" || char === "\n" || char === "|" || char === "&") {
      pushSegment();
      hasSeparator = true;
      continue;
    }

    current += char;
  }

  pushSegment();

  return {
    segments,
    hasSeparator,
    hasEmptySegment: segments.some((segment) => segment.length === 0),
  };
}

function findMatchingCommandPattern(
  command: string,
  patterns: string[] | undefined,
): string | undefined {
  return patterns?.find(
    (pattern) => typeof pattern === "string" && commandMatchesPattern(command, pattern),
  );
}

export function findMatchingDenyCommandPattern(
  command: string,
  patterns: string[] | undefined,
): string | undefined {
  const fullCommandMatch = findMatchingCommandPattern(command, patterns);
  if (fullCommandMatch) return fullCommandMatch;

  const { segments, hasSeparator } = splitCommandForPatternMatching(command);
  if (!hasSeparator) return undefined;

  return segments
    .filter((segment) => segment.length > 0)
    .map((segment) => findMatchingCommandPattern(segment, patterns))
    .find((pattern): pattern is string => Boolean(pattern));
}

export function findMatchingAllowCommandPattern(
  command: string,
  patterns: string[] | undefined,
): string | undefined {
  const { segments, hasSeparator, hasEmptySegment } = splitCommandForPatternMatching(command);
  if (segments.length === 0 || hasEmptySegment) return undefined;

  if (!hasSeparator) return findMatchingCommandPattern(command, patterns);

  const matches = segments.map((segment) => findMatchingCommandPattern(segment, patterns));
  return matches.every((pattern) => Boolean(pattern)) ? matches[0] : undefined;
}

function getStringPatternList(patterns: unknown): string[] {
  return Array.isArray(patterns)
    ? patterns.filter((pattern): pattern is string => typeof pattern === "string")
    : [];
}

function getCommandAllowPatterns(config: SandboxConfig): string[] {
  return getStringPatternList(config.commandPatterns?.allowPatterns);
}

function getCommandDenyPatterns(config: SandboxConfig): string[] {
  return getStringPatternList(config.commandPatterns?.denyPatterns);
}

function formatCommandPatternNotice(decision: CommandPatternDecision): string | undefined {
  if (decision.action === "sandbox") return undefined;

  const pattern = JSON.stringify(decision.pattern);
  if (decision.action === "deny") {
    return `[Sandbox] Command denied by commandPatterns.${decision.listName} (${pattern}); blocked before execution.`;
  }

  return `[Sandbox] Command approved by commandPatterns.${decision.listName} (${pattern}); running without sandbox.`;
}

function prependNoticeToResult<T>(result: AgentToolResult<T>, notice: string): AgentToolResult<T> {
  return {
    ...result,
    content: [{ type: "text", text: notice }, ...result.content],
  };
}

// ── Output analysis ───────────────────────────────────────────────────────────

/** Extract a path from a bash "Operation not permitted" OS sandbox error. */
function extractBlockedWritePath(output: string): string | null {
  const match = output.match(
    /(?:\/bin\/bash|bash|sh): (?:line \d: )?(\/[^\s:]+): Operation not permitted/,
  );
  return match ? match[1] : null;
}

// ── Path pattern matching ─────────────────────────────────────────────────────

export function collapseHomePath(filePath: string): string {
  const home = homedir();
  if (!home || home === "/") return filePath;
  if (filePath === home) return "~";
  if (filePath.startsWith(home + "/")) return "~" + filePath.slice(home.length);
  return filePath;
}

function expandPath(filePath: string, baseCwd = process.cwd()): string {
  const expanded = filePath.replace(/^~(?=$|\/)/, homedir());
  return resolve(baseCwd, expanded);
}

function canonicalizePath(filePath: string, baseCwd = process.cwd()): string {
  const abs = expandPath(filePath, baseCwd);
  try {
    return realpathSync.native(abs);
  } catch {
    // For writes to paths that do not exist yet, resolve symlinks in the nearest
    // existing parent directory, then append the non-existent tail.
    const tail: string[] = [];
    let probe = abs;
    while (!existsSync(probe)) {
      const parent = dirname(probe);
      if (parent === probe) return abs;
      tail.unshift(basename(probe));
      probe = parent;
    }
    try {
      return resolve(realpathSync.native(probe), ...tail);
    } catch {
      return abs;
    }
  }
}

function matchesPattern(filePath: string, patterns: string[], baseCwd = process.cwd()): boolean {
  const abs = canonicalizePath(filePath, baseCwd);
  return patterns.some((p) => {
    const absP = p.includes("*") ? expandPath(p, baseCwd) : canonicalizePath(p, baseCwd);
    if (p.includes("*")) {
      const escaped = absP.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
      return new RegExp(`^${escaped}$`).test(abs);
    }
    const sep = absP.endsWith("/") ? "" : "/";
    return abs === absP || abs.startsWith(absP + sep);
  });
}

function splitShellWords(command: string): string[] {
  const words: string[] = [];
  let current = "";
  let quote: "'" | '"' | null = null;

  const pushCurrent = () => {
    if (current.length > 0) {
      words.push(current);
      current = "";
    }
  };

  for (let i = 0; i < command.length; i++) {
    const char = command[i];

    if (quote) {
      if (char === quote) {
        quote = null;
      } else if (quote === '"' && char === "\\" && i + 1 < command.length) {
        current += command[++i];
      } else {
        current += char;
      }
      continue;
    }

    if (/\s/.test(char)) {
      pushCurrent();
    } else if (char === "'" || char === '"') {
      quote = char;
    } else if (char === "\\" && i + 1 < command.length) {
      current += command[++i];
    } else if ("|&;<>()".includes(char)) {
      pushCurrent();
    } else {
      current += char;
    }
  }

  pushCurrent();
  return words;
}

function looksLikePathToken(value: string): boolean {
  return (
    value === "~" ||
    value.startsWith("~/") ||
    value.startsWith("/") ||
    value.startsWith("./") ||
    value.startsWith("../")
  );
}

function extractPathCandidatesFromCommand(command: string, cwd: string): string[] {
  const candidates = new Set<string>();

  for (const word of splitShellWords(command)) {
    const values = [word];
    const equalsIndex = word.indexOf("=");
    if (equalsIndex > 0 && equalsIndex < word.length - 1) {
      values.push(word.slice(equalsIndex + 1));
    }

    for (const value of values) {
      if (looksLikePathToken(value)) {
        candidates.add(canonicalizePath(value, cwd));
      }
    }
  }

  return [...candidates];
}

// ── Config file updaters (Node.js process — not OS-sandboxed) ─────────────────

function getConfigPaths(cwd: string): {
  globalPath: string;
  projectPath: string;
} {
  return {
    globalPath: join(homedir(), ".pi", "agent", "sandbox.json"),
    projectPath: join(cwd, ".pi", "sandbox.json"),
  };
}

function readOrEmptyConfig(configPath: string): Partial<SandboxConfig> {
  if (!existsSync(configPath)) return {};
  try {
    return JSON.parse(readFileSync(configPath, "utf-8"));
  } catch {
    return {};
  }
}

function writeConfigFile(configPath: string, config: Partial<SandboxConfig>): void {
  mkdirSync(dirname(configPath), { recursive: true });
  writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n", "utf-8");
}

function addDomainToConfig(configPath: string, domain: string): void {
  const config = readOrEmptyConfig(configPath);
  const existing = config.network?.allowedDomains ?? [];
  if (!existing.includes(domain)) {
    config.network = {
      ...config.network,
      allowedDomains: [...existing, domain],
      deniedDomains: config.network?.deniedDomains ?? [],
    };
    writeConfigFile(configPath, config);
  }
}

function addReadPathToConfig(configPath: string, pathToAdd: string): void {
  const config = readOrEmptyConfig(configPath);
  const existing = config.filesystem?.allowRead ?? [];
  if (!existing.includes(pathToAdd)) {
    config.filesystem = {
      ...config.filesystem,
      allowRead: [...existing, pathToAdd],
      denyRead: config.filesystem?.denyRead ?? [],
      allowWrite: config.filesystem?.allowWrite ?? [],
      denyWrite: config.filesystem?.denyWrite ?? [],
    };
    writeConfigFile(configPath, config);
  }
}

function addWritePathToConfig(configPath: string, pathToAdd: string): void {
  const config = readOrEmptyConfig(configPath);
  const existing = config.filesystem?.allowWrite ?? [];
  if (!existing.includes(pathToAdd)) {
    config.filesystem = {
      ...config.filesystem,
      allowWrite: [...existing, pathToAdd],
      denyRead: config.filesystem?.denyRead ?? [],
      denyWrite: config.filesystem?.denyWrite ?? [],
    };
    writeConfigFile(configPath, config);
  }
}

function addCommandAllowPatternToConfig(configPath: string, pattern: string): void {
  const config = readOrEmptyConfig(configPath);
  const existing = config.commandPatterns?.allowPatterns ?? [];
  if (!existing.includes(pattern)) {
    config.commandPatterns = {
      ...config.commandPatterns,
      allowPatterns: [...existing, pattern],
      denyPatterns: config.commandPatterns?.denyPatterns ?? [],
    };
    writeConfigFile(configPath, config);
  }
}

// ── Sandboxed bash ops ────────────────────────────────────────────────────────

export function protectBangsForSandboxWrap(command: string): {
  protectedCommand: string;
  sentinel: string;
} {
  let sentinel = `__PI_SANDBOX_BANG_${randomUUID().replaceAll("-", "")}__`;
  while (command.includes(sentinel)) {
    sentinel = `__PI_SANDBOX_BANG_${randomUUID().replaceAll("-", "")}__`;
  }

  return {
    protectedCommand: command.replaceAll("!", sentinel),
    sentinel,
  };
}

export function restoreBangsAfterSandboxWrap(wrappedCommand: string, sentinel: string): string {
  return wrappedCommand.replaceAll(sentinel, "!");
}

function createSandboxedBashOps(shellPath?: string): BashOperations {
  return {
    async exec(command, cwd, { onData, signal, timeout, env }) {
      if (!existsSync(cwd)) {
        throw new Error(`Working directory does not exist: ${cwd}`);
      }

      const { shell, args } = getShellConfig(shellPath);
      const { protectedCommand, sentinel } = protectBangsForSandboxWrap(command);
      let wrappedCommand = await SandboxManager.wrapWithSandbox(protectedCommand, shell);
      wrappedCommand = restoreBangsAfterSandboxWrap(wrappedCommand, sentinel);
      let cleanedUp = false;
      const cleanupSandboxMounts = () => {
        if (cleanedUp) return;
        cleanedUp = true;
        try {
          SandboxManager.cleanupAfterCommand();
        } catch (e) {
          console.error(`Warning: Failed to clean up sandbox mount points: ${e}`);
        }
      };

      return new Promise((resolve, reject) => {
        const child = spawn(shell, [...args, wrappedCommand], {
          cwd,
          env,
          detached: true,
          stdio: ["ignore", "pipe", "pipe"],
        });

        let timedOut = false;
        let timeoutHandle: NodeJS.Timeout | undefined;

        if (timeout !== undefined && timeout > 0) {
          timeoutHandle = setTimeout(() => {
            timedOut = true;
            if (child.pid) {
              try {
                process.kill(-child.pid, "SIGKILL");
              } catch {
                child.kill("SIGKILL");
              }
            }
          }, timeout * 1000);
        }

        child.stdout?.on("data", onData);
        child.stderr?.on("data", onData);

        child.on("error", (err) => {
          if (timeoutHandle) clearTimeout(timeoutHandle);
          cleanupSandboxMounts();
          reject(err);
        });

        const onAbort = () => {
          if (child.pid) {
            try {
              process.kill(-child.pid, "SIGKILL");
            } catch {
              child.kill("SIGKILL");
            }
          }
        };

        signal?.addEventListener("abort", onAbort, { once: true });

        child.on("close", (code) => {
          if (timeoutHandle) clearTimeout(timeoutHandle);
          signal?.removeEventListener("abort", onAbort);
          cleanupSandboxMounts();

          if (signal?.aborted) {
            reject(new Error("aborted"));
          } else if (timedOut) {
            reject(new Error(`timeout:${timeout}`));
          } else {
            resolve({ exitCode: code });
          }
        });
      });
    },
  };
}

// ── Extension ─────────────────────────────────────────────────────────────────

export default function (pi: ExtensionAPI) {
  pi.registerFlag("no-sandbox", {
    description: "Disable OS-level sandboxing for bash commands",
    type: "boolean",
    default: false,
  });

  const localCwd = process.cwd();
  const userShellPath = SettingsManager.create(localCwd).getShellPath();
  const localBash = createBashToolDefinition(localCwd, {
    shellPath: userShellPath,
  });

  let sandboxEnabled = false;
  let sandboxInitialized = false;

  // Session-temporary allowances — held in JS memory, not accessible by the agent.
  // These are added on top of whatever is in the config files.
  const sessionAllowedDomains: string[] = [];
  const sessionAllowedReadPaths: string[] = [];
  const sessionAllowedWritePaths: string[] = [];
  const sessionAllowedCommandAllowPatterns: string[] = [];

  // ── Effective config helpers ────────────────────────────────────────────────

  function getEffectiveAllowedDomains(cwd: string): string[] {
    const config = loadConfig(cwd);
    return [...(config.network?.allowedDomains ?? []), ...sessionAllowedDomains];
  }

  function getEffectiveAllowRead(cwd: string): string[] {
    const config = loadConfig(cwd);
    return [...(config.filesystem?.allowRead ?? []), ...sessionAllowedReadPaths];
  }

  function getEffectiveAllowWrite(cwd: string): string[] {
    const config = loadConfig(cwd);
    return [...(config.filesystem?.allowWrite ?? []), ...sessionAllowedWritePaths];
  }

  function getBlockedReadPathsForCommand(command: string, cwd: string): string[] {
    const config = loadConfig(cwd);
    const denyRead = config.filesystem?.denyRead ?? [];
    if (denyRead.length === 0) return [];

    const effectiveAllowRead = getEffectiveAllowRead(cwd);
    return extractPathCandidatesFromCommand(command, cwd).filter(
      (path) =>
        matchesPattern(path, denyRead, cwd) && !matchesPattern(path, effectiveAllowRead, cwd),
    );
  }

  function getCommandPatternDecision(command: string, cwd: string): CommandPatternDecision {
    const config = loadConfig(cwd);
    const deniedPattern = findMatchingDenyCommandPattern(command, getCommandDenyPatterns(config));
    if (deniedPattern) {
      return {
        action: "deny",
        listName: "denyPatterns",
        pattern: deniedPattern,
      };
    }

    const sessionAllowedPattern = findMatchingAllowCommandPattern(
      command,
      sessionAllowedCommandAllowPatterns,
    );
    if (sessionAllowedPattern) {
      return {
        action: "allow",
        listName: "allowPatterns",
        pattern: sessionAllowedPattern,
      };
    }

    const allowedPattern = findMatchingAllowCommandPattern(
      command,
      getCommandAllowPatterns(config),
    );
    if (allowedPattern) {
      return {
        action: "allow",
        listName: "allowPatterns",
        pattern: allowedPattern,
      };
    }

    return { action: "sandbox" };
  }

  // ── Sandbox reinitialize ────────────────────────────────────────────────────
  // Called after granting a session/permanent allowance so the OS-level sandbox
  // picks up the new rules before the next bash subprocess starts.

  async function reinitializeSandbox(cwd: string): Promise<void> {
    if (!sandboxInitialized) return;
    const config = loadConfig(cwd);
    const configExt = config as unknown as { allowBrowserProcess?: boolean };
    try {
      const network = {
        ...config.network,
        allowedDomains: [...(config.network?.allowedDomains ?? []), ...sessionAllowedDomains],
        deniedDomains: config.network?.deniedDomains ?? [],
      };
      await SandboxManager.reset();
      await SandboxManager.initialize(
        {
          network,
          filesystem: {
            ...config.filesystem,
            denyRead: config.filesystem?.denyRead ?? [],
            allowRead: [...(config.filesystem?.allowRead ?? []), ...sessionAllowedReadPaths],
            allowWrite: [...(config.filesystem?.allowWrite ?? []), ...sessionAllowedWritePaths],
            denyWrite: config.filesystem?.denyWrite ?? [],
          },
          allowBrowserProcess: configExt.allowBrowserProcess,
          enableWeakerNetworkIsolation: true,
        },
        createNetworkAskCallback(network.allowedDomains),
      );
    } catch (e) {
      console.error(`Warning: Failed to reinitialize sandbox: ${e}`);
    }
  }

  // ── UI prompts ──────────────────────────────────────────────────────────────

  type PermissionAction = "abort" | "session" | "project" | "global";
  type PermissionTarget = "resource" | "command";

  interface PromptOption {
    label: string;
    action: PermissionAction;
    confirm?: boolean;
    hint?: string;
  }

  interface PermissionPromptResult {
    action: PermissionAction;
    target: PermissionTarget;
    value: string;
  }

  const RESOURCE_PERMISSION_OPTIONS: PromptOption[] = [
    { label: "Allow for this session only", action: "session" },
    { label: "Abort (keep blocked)", action: "abort" },
    {
      label: "Allow for this project",
      action: "project",
      confirm: true,
      hint: "→ .pi/sandbox.json",
    },
    {
      label: "Allow for all projects",
      action: "global",
      confirm: true,
      hint: "→ ~/.pi/agent/sandbox.json",
    },
  ];

  const COMMAND_PERMISSION_OPTIONS: PromptOption[] = [
    {
      label: "Allow this command pattern for this session only",
      action: "session",
    },
    { label: "Abort (keep blocked)", action: "abort" },
    {
      label: "Add command allowPattern for this project",
      action: "project",
      confirm: true,
      hint: "→ .pi/sandbox.json commandPatterns.allowPatterns",
    },
    {
      label: "Add command allowPattern for all projects",
      action: "global",
      confirm: true,
      hint: "→ ~/.pi/agent/sandbox.json commandPatterns.allowPatterns",
    },
  ];

  function isPrintableInput(data: string): boolean {
    if (data.length === 0) return false;
    for (let i = 0; i < data.length; i++) {
      const code = data.charCodeAt(i);
      if (code < 32 || code === 127) return false;
    }
    return true;
  }

  async function showPermissionPrompt(
    ctx: ExtensionContext,
    title: string,
    resourceLabel: string,
    initialResourceValue: string,
    command?: string,
  ): Promise<PermissionPromptResult> {
    if (!ctx.hasUI) {
      return {
        action: "abort",
        target: "resource",
        value: initialResourceValue,
      };
    }

    const result = await ctx.ui.custom<PermissionPromptResult>((tui, theme, _kb, done) => {
      let selectedIndex = 0;
      let pendingAction: PermissionAction | null = null;
      let target: PermissionTarget = "resource";
      let resourceValue = initialResourceValue;
      let commandValue = command ?? "";

      function currentValue(): string {
        return target === "command" ? commandValue : resourceValue;
      }

      function setCurrentValue(value: string): void {
        if (target === "command") {
          commandValue = value;
        } else {
          resourceValue = value;
        }
      }

      function currentOptions(): PromptOption[] {
        return target === "command" ? COMMAND_PERMISSION_OPTIONS : RESOURCE_PERMISSION_OPTIONS;
      }

      function resolve(action: PermissionAction) {
        done({ action, target, value: currentValue().trim() });
      }

      function switchTarget(): void {
        if (!command) return;
        target = target === "command" ? "resource" : "command";
        selectedIndex = 0;
        pendingAction = null;
        tui.requestRender();
      }

      return {
        render(width: number): string[] {
          const lines: string[] = [];
          const options = currentOptions();
          const targetLabel = target === "command" ? "Command allowPattern" : resourceLabel;

          lines.push(truncateToWidth(theme.fg("warning", title), width));
          lines.push("");
          lines.push(truncateToWidth(`${theme.fg("accent", targetLabel)}:`, width));
          lines.push(truncateToWidth(`  ${currentValue() || theme.fg("dim", "(empty)")}`, width));
          if (command) {
            lines.push(
              truncateToWidth(
                theme.fg(
                  "dim",
                  target === "command"
                    ? "Editing command allowPattern. Press Tab to edit the blocked value instead."
                    : "Editing blocked value. Press Tab to allow the whole command by pattern instead.",
                ),
                width,
              ),
            );
          }
          lines.push("");

          for (let i = 0; i < options.length; i++) {
            const opt = options[i];
            const isSelected = i === selectedIndex;
            const isPending = pendingAction === opt.action;

            const prefix = isSelected ? " → " : "   ";
            let label = opt.label;

            if (opt.hint) {
              label += `  ${theme.fg("dim", opt.hint)}`;
            }

            if (isPending) {
              label += `  ${theme.fg("warning", "→ press Enter to confirm")}`;
            }

            lines.push(truncateToWidth(`${prefix}${label}`, width));
          }

          lines.push("");
          const footer = pendingAction
            ? "enter confirm  esc cancel"
            : "type edit  backspace delete  ↑↓ choose action  enter select  tab switch  esc cancel";
          lines.push(truncateToWidth(theme.fg("dim", footer), width));

          return lines;
        },

        handleInput(data: string): void {
          if (matchesKey(data, Key.escape) || matchesKey(data, Key.ctrl("c"))) {
            resolve("abort");
            return;
          }

          if (matchesKey(data, Key.tab)) {
            switchTarget();
            return;
          }

          if (matchesKey(data, Key.enter)) {
            const options = currentOptions();
            const option = options[selectedIndex];
            const action = option?.action ?? "abort";
            if (action !== "abort" && !currentValue().trim()) {
              pendingAction = null;
              tui.requestRender();
              return;
            }
            if (pendingAction) {
              resolve(pendingAction);
            } else if (option?.confirm) {
              pendingAction = action;
              tui.requestRender();
            } else {
              resolve(action);
            }
            return;
          }

          if (matchesKey(data, Key.up)) {
            selectedIndex = Math.max(0, selectedIndex - 1);
            pendingAction = null;
            tui.requestRender();
            return;
          }
          if (matchesKey(data, Key.down)) {
            selectedIndex = Math.min(currentOptions().length - 1, selectedIndex + 1);
            pendingAction = null;
            tui.requestRender();
            return;
          }

          if (matchesKey(data, Key.backspace) || matchesKey(data, Key.delete)) {
            setCurrentValue(currentValue().slice(0, -1));
            pendingAction = null;
            tui.requestRender();
            return;
          }

          if (matchesKey(data, Key.ctrl("u"))) {
            setCurrentValue("");
            pendingAction = null;
            tui.requestRender();
            return;
          }

          if (isPrintableInput(data)) {
            setCurrentValue(currentValue() + data);
            pendingAction = null;
            tui.requestRender();
          }
        },

        invalidate(): void {
          // no-op
        },
      };
    });

    return (
      result ?? {
        action: "abort",
        target: "resource",
        value: initialResourceValue,
      }
    );
  }

  async function promptDomainBlock(
    ctx: ExtensionContext,
    domain: string,
    command?: string,
  ): Promise<PermissionPromptResult> {
    return showPermissionPrompt(
      ctx,
      `🌐 Network blocked: "${domain}" is not in allowedDomains`,
      "Allowed domain",
      domain,
      command,
    );
  }

  async function promptReadBlock(
    ctx: ExtensionContext,
    filePath: string,
    command?: string,
  ): Promise<PermissionPromptResult> {
    const displayPath = collapseHomePath(filePath);
    return showPermissionPrompt(
      ctx,
      `📖 Read blocked: "${displayPath}" is not in allowRead`,
      "Allowed read path",
      displayPath,
      command,
    );
  }

  async function promptWriteBlock(
    ctx: ExtensionContext,
    filePath: string,
    command?: string,
  ): Promise<PermissionPromptResult> {
    const displayPath = collapseHomePath(filePath);
    return showPermissionPrompt(
      ctx,
      `📝 Write blocked: "${displayPath}" is not in allowWrite`,
      "Allowed write path",
      displayPath,
      command,
    );
  }

  function warnIfAllDomainsAllowed(ctx: ExtensionContext, config: SandboxConfig): void {
    if (!allowsAllDomains(config.network?.allowedDomains)) return;
    ctx.ui.notify(
      '⚠️ Network sandbox allows all domains because network.allowedDomains contains "*". ' +
        'Only use this intentionally; remove "*" to restore per-domain prompts.',
      "warning",
    );
  }

  function warnIfBroadCommandPatterns(ctx: ExtensionContext, config: SandboxConfig): void {
    if (getCommandAllowPatterns(config).includes("*")) {
      ctx.ui.notify(
        '⚠️ Bash sandbox is bypassed for all commands because commandPatterns.allowPatterns contains "*". ' +
          'Only use this intentionally; remove "*" to restore sandboxed command execution.',
        "warning",
      );
    }

    if (getCommandDenyPatterns(config).includes("*")) {
      ctx.ui.notify(
        '⚠️ All bash commands are blocked because commandPatterns.denyPatterns contains "*".',
        "warning",
      );
    }
  }

  function formatCommandPatternStatusSuffix(config: SandboxConfig): string {
    const allowCount = getCommandAllowPatterns(config).length;
    const denyCount = getCommandDenyPatterns(config).length;
    const labels: string[] = [];

    if (allowCount > 0) labels.push(`${allowCount} allow pattern${allowCount === 1 ? "" : "s"}`);
    if (denyCount > 0) labels.push(`${denyCount} deny pattern${denyCount === 1 ? "" : "s"}`);

    return labels.length > 0 ? `, ${labels.join(", ")}` : "";
  }

  // ── Apply allowance choices ─────────────────────────────────────────────────

  async function applyDomainChoice(
    choice: Exclude<PermissionAction, "abort">,
    domain: string,
    cwd: string,
  ): Promise<void> {
    const { globalPath, projectPath } = getConfigPaths(cwd);
    if (!sessionAllowedDomains.includes(domain)) sessionAllowedDomains.push(domain);
    if (choice === "project") addDomainToConfig(projectPath, domain);
    if (choice === "global") addDomainToConfig(globalPath, domain);
    await reinitializeSandbox(cwd);
  }

  async function applyReadChoice(
    choice: Exclude<PermissionAction, "abort">,
    filePath: string,
    cwd: string,
  ): Promise<void> {
    const { globalPath, projectPath } = getConfigPaths(cwd);
    if (!sessionAllowedReadPaths.includes(filePath)) sessionAllowedReadPaths.push(filePath);
    if (choice === "project") addReadPathToConfig(projectPath, filePath);
    if (choice === "global") addReadPathToConfig(globalPath, filePath);
    await reinitializeSandbox(cwd);
  }

  async function applyWriteChoice(
    choice: Exclude<PermissionAction, "abort">,
    filePath: string,
    cwd: string,
  ): Promise<void> {
    const { globalPath, projectPath } = getConfigPaths(cwd);
    if (!sessionAllowedWritePaths.includes(filePath)) sessionAllowedWritePaths.push(filePath);
    if (choice === "project") addWritePathToConfig(projectPath, filePath);
    if (choice === "global") addWritePathToConfig(globalPath, filePath);
    await reinitializeSandbox(cwd);
  }

  async function applyCommandAllowPatternChoice(
    choice: Exclude<PermissionAction, "abort">,
    pattern: string,
    cwd: string,
  ): Promise<void> {
    const { globalPath, projectPath } = getConfigPaths(cwd);
    if (!sessionAllowedCommandAllowPatterns.includes(pattern)) {
      sessionAllowedCommandAllowPatterns.push(pattern);
    }
    if (choice === "project") addCommandAllowPatternToConfig(projectPath, pattern);
    if (choice === "global") addCommandAllowPatternToConfig(globalPath, pattern);
    await reinitializeSandbox(cwd);
  }

  // ── Bash tool — with write-block detection and retry ───────────────────────

  pi.registerTool({
    ...localBash,
    label: "bash (sandboxed)",
    async execute(id, params, signal, onUpdate, ctx) {
      const command = (params as { command?: unknown }).command;
      const commandDecision: CommandPatternDecision =
        sandboxEnabled && typeof command === "string"
          ? getCommandPatternDecision(command, ctx?.cwd ?? localCwd)
          : { action: "sandbox" };
      const commandPatternNotice = formatCommandPatternNotice(commandDecision);
      const sandboxBypassed = commandDecision.action === "allow";
      const updateWithNotice =
        commandPatternNotice && onUpdate
          ? (partial: AgentToolResult<any>) =>
              onUpdate(prependNoticeToResult(partial, commandPatternNotice))
          : onUpdate;

      if (commandDecision.action === "deny") {
        const result = {
          content: [
            {
              type: "text" as const,
              text:
                commandPatternNotice ??
                "[Sandbox] Command denied by commandPatterns.denyPatterns; blocked before execution.",
            },
          ],
          details: {},
        };
        onUpdate?.(result);
        return result;
      }

      const runBash = () => {
        if (sandboxBypassed || !sandboxEnabled || !sandboxInitialized) {
          return localBash.execute(id, params, signal, updateWithNotice, ctx);
        }
        const sandboxedBash = createBashToolDefinition(localCwd, {
          operations: createSandboxedBashOps(userShellPath),
          shellPath: userShellPath,
        });
        return sandboxedBash.execute(id, params, signal, updateWithNotice, ctx);
      };

      let result: AgentToolResult<any>;
      try {
        result = await runBash();
        if (commandPatternNotice) result = prependNoticeToResult(result, commandPatternNotice);
      } catch (e) {
        if (!(e instanceof Error)) throw e;
        if (!e.message.includes("Operation not permitted")) {
          if (commandPatternNotice) throw new Error(`${commandPatternNotice}\n\n${e.message}`);
          throw e;
        }

        result = {
          content: [
            {
              type: "text",
              text: `Error: Command failed with OS-level sandbox restriction: ${e.message}`,
            },
          ],
          details: {},
        };
      }

      // Post-execution: detect OS-level write block and offer to allow.
      if (!sandboxBypassed && sandboxEnabled && sandboxInitialized && ctx?.hasUI) {
        const outputText = result.content
          .filter((c: any) => c.type === "text")
          .map((c: any) => c.text)
          .join("\n");

        const blockedPath = extractBlockedWritePath(outputText);
        if (blockedPath) {
          const choice = await promptWriteBlock(
            ctx,
            blockedPath,
            typeof command === "string" ? command : undefined,
          );
          if (choice.action !== "abort") {
            if (choice.target === "command") {
              await applyCommandAllowPatternChoice(choice.action, choice.value, ctx.cwd);
              onUpdate?.({
                content: [
                  {
                    type: "text",
                    text: `\n--- Command allowPattern added for "${choice.value}", retrying without sandbox ---\n`,
                  },
                ],
                details: {},
              });
              return localBash.execute(id, params, signal, updateWithNotice, ctx);
            }

            await applyWriteChoice(choice.action, choice.value, ctx.cwd);

            // Check if denyWrite would still block it even after allowing.
            const config = loadConfig(ctx.cwd);
            const { projectPath, globalPath } = getConfigPaths(ctx.cwd);
            if (matchesPattern(choice.value, config.filesystem?.denyWrite ?? [])) {
              ctx.ui.notify(
                `⚠️ "${choice.value}" was added to allowWrite, but it is also in denyWrite and will remain blocked.\n` +
                  `Check denyWrite in:\n  ${projectPath}\n  ${globalPath}`,
                "warning",
              );
              return result;
            }

            onUpdate?.({
              content: [
                {
                  type: "text",
                  text: `\n--- Write access granted for "${choice.value}", retrying ---\n`,
                },
              ],
              details: {},
            });
            return runBash();
          }
        }
      }

      return result;
    },
  });

  // ── user_bash — network pre-check ──────────────────────────────────────────

  pi.on("user_bash", async (event, ctx) => {
    if (!sandboxEnabled || !sandboxInitialized) return;

    const commandDecision = getCommandPatternDecision(event.command, ctx.cwd);
    const commandPatternNotice = formatCommandPatternNotice(commandDecision);
    if (commandDecision.action === "deny") {
      return {
        result: {
          output:
            commandPatternNotice ??
            "[Sandbox] Command denied by commandPatterns.denyPatterns; blocked before execution.",
          exitCode: 1,
          cancelled: false,
          truncated: false,
        },
      };
    }
    if (commandDecision.action === "allow") return;

    for (const blockedPath of getBlockedReadPathsForCommand(event.command, ctx.cwd)) {
      const choice = await promptReadBlock(ctx, blockedPath, event.command);
      if (choice.action === "abort") {
        return {
          result: {
            output: `Blocked: read access to "${blockedPath}" is not in allowRead. Use /sandbox to review your config.`,
            exitCode: 1,
            cancelled: false,
            truncated: false,
          },
        };
      }
      if (choice.target === "command") {
        await applyCommandAllowPatternChoice(choice.action, choice.value, ctx.cwd);
        return;
      }
      await applyReadChoice(choice.action, choice.value, ctx.cwd);
    }

    const domains = extractDomainsFromCommand(event.command);
    const effectiveDomains = getEffectiveAllowedDomains(ctx.cwd);

    for (const domain of domains) {
      if (!domainIsAllowed(domain, effectiveDomains)) {
        const choice = await promptDomainBlock(ctx, domain, event.command);
        if (choice.action === "abort") {
          return {
            result: {
              output: `Blocked: "${domain}" is not in allowedDomains. Use /sandbox to review your config.`,
              exitCode: 1,
              cancelled: false,
              truncated: false,
            },
          };
        }
        if (choice.target === "command") {
          await applyCommandAllowPatternChoice(choice.action, choice.value, ctx.cwd);
          return;
        }
        await applyDomainChoice(choice.action, choice.value, ctx.cwd);
      }
    }

    return { operations: createSandboxedBashOps(userShellPath) };
  });

  // ── tool_call — network pre-check for bash, path policy for read/write/edit

  pi.on("tool_call", async (event, ctx) => {
    if (!sandboxEnabled) return;

    const config = loadConfig(ctx.cwd);
    if (!config.enabled) return;

    const { projectPath, globalPath } = getConfigPaths(ctx.cwd);

    // Network pre-check for bash tool calls.
    if (sandboxInitialized && isToolCallEventType("bash", event)) {
      const commandDecision = getCommandPatternDecision(event.input.command, ctx.cwd);
      if (commandDecision.action === "deny") {
        return {
          block: true,
          reason:
            `${formatCommandPatternNotice(commandDecision)}\n` +
            `To change this, edit commandPatterns.denyPatterns in:\n  ${projectPath}\n  ${globalPath}`,
        };
      }
      if (commandDecision.action === "allow") return;

      for (const blockedPath of getBlockedReadPathsForCommand(event.input.command, ctx.cwd)) {
        const choice = await promptReadBlock(ctx, blockedPath, event.input.command);
        if (choice.action === "abort") {
          return {
            block: true,
            reason: `Read access to "${blockedPath}" is blocked (not in allowRead).`,
          };
        }
        if (choice.target === "command") {
          await applyCommandAllowPatternChoice(choice.action, choice.value, ctx.cwd);
          return;
        }
        await applyReadChoice(choice.action, choice.value, ctx.cwd);
      }

      const domains = extractDomainsFromCommand(event.input.command);
      const effectiveDomains = getEffectiveAllowedDomains(ctx.cwd);
      for (const domain of domains) {
        if (!domainIsAllowed(domain, effectiveDomains)) {
          const choice = await promptDomainBlock(ctx, domain, event.input.command);
          if (choice.action === "abort") {
            return {
              block: true,
              reason: `Network access to "${domain}" is blocked (not in allowedDomains).`,
            };
          }
          if (choice.target === "command") {
            await applyCommandAllowPatternChoice(choice.action, choice.value, ctx.cwd);
            return;
          }
          await applyDomainChoice(choice.action, choice.value, ctx.cwd);
        }
      }
    }

    // Path policy: read tool.
    //   - If the path is already in effectiveAllowRead, allow silently.
    //   - Otherwise always prompt, regardless of denyRead.
    //   - Granting (session or permanent) adds to allowRead, which overrides denyRead.
    //   - denyRead is never a hard-block on its own — it just sets the default
    //     denied state that the prompt can override.
    if (isToolCallEventType("read", event)) {
      const filePath = canonicalizePath(event.input.path);
      const effectiveAllowRead = getEffectiveAllowRead(ctx.cwd);

      if (!matchesPattern(filePath, effectiveAllowRead)) {
        const choice = await promptReadBlock(ctx, filePath);
        if (choice.action === "abort") {
          return {
            block: true,
            reason: `Sandbox: read access denied for "${filePath}"`,
          };
        }
        await applyReadChoice(choice.action, choice.value, ctx.cwd);
        // Allowed — fall through, tool runs.
        return;
      }
    }

    // Path policy: write/edit — prompt for allowWrite, hard-block for denyWrite.
    if (isToolCallEventType("write", event) || isToolCallEventType("edit", event)) {
      const path = canonicalizePath((event.input as { path: string }).path);
      const allowWrite = getEffectiveAllowWrite(ctx.cwd);
      const denyWrite = config.filesystem?.denyWrite ?? [];

      // denyWrite takes precedence and is never prompted.
      if (matchesPattern(path, denyWrite)) {
        return {
          block: true,
          reason:
            `Sandbox: write access denied for "${path}" (in denyWrite). ` +
            `To change this, edit denyWrite in:\n  ${projectPath}\n  ${globalPath}`,
        };
      }

      if (shouldPromptForWrite(path, allowWrite, matchesPattern)) {
        const choice = await promptWriteBlock(ctx, path);
        if (choice.action === "abort") {
          return {
            block: true,
            reason: `Sandbox: write access denied for "${path}" (not in allowWrite)`,
          };
        }
        await applyWriteChoice(choice.action, choice.value, ctx.cwd);
        // Allowed — fall through, tool runs.
        return;
      }
    }
  });

  // ── session_start ───────────────────────────────────────────────────────────

  pi.on("session_start", async (_event, ctx) => {
    const noSandbox = pi.getFlag("no-sandbox") as boolean;

    if (noSandbox) {
      sandboxEnabled = false;
      ctx.ui.notify("Sandbox disabled via --no-sandbox", "warning");
      return;
    }

    const config = loadConfig(ctx.cwd);

    if (!config.enabled) {
      sandboxEnabled = false;
      ctx.ui.notify("Sandbox disabled via config", "info");
      return;
    }

    const platform = process.platform;
    if (platform !== "darwin" && platform !== "linux") {
      sandboxEnabled = false;
      ctx.ui.notify(`Sandbox not supported on ${platform}`, "warning");
      return;
    }

    try {
      const configExt = config as unknown as {
        ignoreViolations?: Record<string, string[]>;
        enableWeakerNestedSandbox?: boolean;
        allowBrowserProcess?: boolean;
      };

      await SandboxManager.initialize(
        {
          network: config.network,
          filesystem: config.filesystem,
          ignoreViolations: configExt.ignoreViolations,
          enableWeakerNestedSandbox: configExt.enableWeakerNestedSandbox,
          allowBrowserProcess: configExt.allowBrowserProcess,
          enableWeakerNetworkIsolation: true,
        },
        createNetworkAskCallback(config.network?.allowedDomains ?? []),
      );

      // Make Node's built-in fetch() honour HTTP_PROXY / HTTPS_PROXY in this
      // process and any child processes that inherit the environment.
      // NODE_USE_ENV_PROXY avoids NODE_OPTIONS allowlisting issues on older Node
      // versions while still propagating naturally to child `node` processes.
      // fetch() supports this on Node 22.21.0+ and 24.0.0+.
      const [nodeMajor, nodeMinor] = process.versions.node.split(".").map(Number);
      const supportsEnvProxy = (nodeMajor === 22 && nodeMinor >= 21) || nodeMajor >= 24;
      if (supportsEnvProxy) {
        process.env.NODE_USE_ENV_PROXY ??= "1";
      }

      sandboxEnabled = true;
      sandboxInitialized = true;

      warnIfAllDomainsAllowed(ctx, config);
      warnIfBroadCommandPatterns(ctx, config);

      const networkLabel = allowsAllDomains(config.network?.allowedDomains)
        ? "all domains"
        : `${config.network?.allowedDomains?.length ?? 0} domains`;
      const writeCount = config.filesystem?.allowWrite?.length ?? 0;
      const commandPatternLabel = formatCommandPatternStatusSuffix(config);
      ctx.ui.setStatus(
        "sandbox",
        ctx.ui.theme.fg(
          "accent",
          `🔒 Sandbox: ${networkLabel}, ${writeCount} write paths${commandPatternLabel}`,
        ),
      );
    } catch (err) {
      sandboxEnabled = false;
      ctx.ui.notify(
        `Sandbox initialization failed: ${err instanceof Error ? err.message : err}`,
        "error",
      );
    }
  });

  // ── session_shutdown ────────────────────────────────────────────────────────

  pi.on("session_shutdown", async () => {
    if (sandboxInitialized) {
      try {
        await SandboxManager.reset();
      } catch {
        // Ignore cleanup errors
      }
    }
  });

  // ── /sandbox command ────────────────────────────────────────────────────────

  pi.registerCommand("sandbox-enable", {
    description: "Enable the sandbox for this session",
    handler: async (_args, ctx) => {
      if (sandboxEnabled) {
        ctx.ui.notify("Sandbox is already enabled", "info");
        return;
      }

      const config = loadConfig(ctx.cwd);
      const platform = process.platform;
      if (platform !== "darwin" && platform !== "linux") {
        ctx.ui.notify(`Sandbox not supported on ${platform}`, "warning");
        return;
      }

      try {
        const configExt = config as unknown as {
          ignoreViolations?: Record<string, string[]>;
          enableWeakerNestedSandbox?: boolean;
          allowBrowserProcess?: boolean;
        };

        await SandboxManager.initialize(
          {
            network: config.network,
            filesystem: config.filesystem,
            ignoreViolations: configExt.ignoreViolations,
            enableWeakerNestedSandbox: configExt.enableWeakerNestedSandbox,
            allowBrowserProcess: configExt.allowBrowserProcess,
            enableWeakerNetworkIsolation: true,
          },
          createNetworkAskCallback(config.network?.allowedDomains ?? []),
        );

        sandboxEnabled = true;
        sandboxInitialized = true;

        warnIfAllDomainsAllowed(ctx, config);
        warnIfBroadCommandPatterns(ctx, config);

        const networkLabel = allowsAllDomains(config.network?.allowedDomains)
          ? "all domains"
          : `${config.network?.allowedDomains?.length ?? 0} domains`;
        const writeCount = config.filesystem?.allowWrite?.length ?? 0;
        const commandPatternLabel = formatCommandPatternStatusSuffix(config);
        ctx.ui.setStatus(
          "sandbox",
          ctx.ui.theme.fg(
            "accent",
            `🔒 Sandbox: ${networkLabel}, ${writeCount} write paths${commandPatternLabel}`,
          ),
        );
        ctx.ui.notify("Sandbox enabled", "info");
      } catch (err) {
        ctx.ui.notify(
          `Sandbox initialization failed: ${err instanceof Error ? err.message : err}`,
          "error",
        );
      }
    },
  });

  pi.registerCommand("sandbox-disable", {
    description: "Disable the sandbox for this session",
    handler: async (_args, ctx) => {
      if (!sandboxEnabled) {
        ctx.ui.notify("Sandbox is already disabled", "info");
        return;
      }

      if (sandboxInitialized) {
        try {
          await SandboxManager.reset();
        } catch {
          // Ignore cleanup errors
        }
      }

      sandboxEnabled = false;
      sandboxInitialized = false;
      ctx.ui.setStatus("sandbox", "");
      ctx.ui.notify("Sandbox disabled", "info");
    },
  });

  pi.registerCommand("sandbox", {
    description: "Show sandbox configuration",
    handler: async (_args, ctx) => {
      if (!sandboxEnabled) {
        ctx.ui.notify("Sandbox is disabled", "info");
        return;
      }

      const config = loadConfig(ctx.cwd);
      const { globalPath, projectPath } = getConfigPaths(ctx.cwd);
      const commandAllowPatterns = getCommandAllowPatterns(config);
      const commandDenyPatterns = getCommandDenyPatterns(config);

      const lines = [
        "Sandbox Configuration",
        `  Project config: ${projectPath}`,
        `  Global config:  ${globalPath}`,
        "",
        "Command patterns (bash + !cmd):",
        `  Allow patterns: ${commandAllowPatterns.join(", ") || "(none)"}`,
        ...(commandAllowPatterns.includes("*")
          ? ['  ⚠️ allowPatterns "*" bypasses the sandbox for every command.']
          : []),
        ...(sessionAllowedCommandAllowPatterns.length > 0
          ? [`  Session allow patterns: ${sessionAllowedCommandAllowPatterns.join(", ")}`]
          : []),
        `  Deny patterns:  ${commandDenyPatterns.join(", ") || "(none)"}`,
        ...(commandDenyPatterns.includes("*")
          ? ['  ⚠️ denyPatterns "*" blocks every command.']
          : []),
        "",
        "Network (bash + !cmd):",
        `  Allowed domains: ${config.network?.allowedDomains?.join(", ") || "(none)"}`,
        ...(allowsAllDomains(config.network?.allowedDomains)
          ? ['  ⚠️ "*" allows all domains and disables per-domain prompts.']
          : []),
        `  Denied domains:  ${config.network?.deniedDomains?.join(", ") || "(none)"}`,
        ...(sessionAllowedDomains.length > 0
          ? [`  Session allowed: ${sessionAllowedDomains.join(", ")}`]
          : []),
        "",
        "Filesystem (bash + read/write/edit tools):",
        `  Deny Read:   ${config.filesystem?.denyRead?.join(", ") || "(none)"}`,
        `  Allow Read:  ${config.filesystem?.allowRead?.join(", ") || "(none)"}`,
        `  Allow Write: ${config.filesystem?.allowWrite?.join(", ") || "(none)"}`,
        `  Deny Write:  ${config.filesystem?.denyWrite?.join(", ") || "(none)"}`,
        ...(sessionAllowedReadPaths.length > 0
          ? [`  Session read:  ${sessionAllowedReadPaths.join(", ")}`]
          : []),
        ...(sessionAllowedWritePaths.length > 0
          ? [`  Session write: ${sessionAllowedWritePaths.join(", ")}`]
          : []),
        "",
        "Note: commandPatterns.denyPatterns hard-blocks matching bash commands.",
        "Note: commandPatterns.allowPatterns bypasses all bash sandboxing for matching commands.",
        "Note: commandPatterns.denyPatterns takes precedence over allowPatterns.",
        "Note: ALL reads are prompted unless the path is already in allowRead.",
        "Note: denyRead is not a hard-block — granting a prompt adds to allowRead, overriding denyRead.",
        "Note: denyWrite takes PRECEDENCE over allowWrite and is never prompted.",
      ];
      ctx.ui.notify(lines.join("\n"), "info");
    },
  });
}
