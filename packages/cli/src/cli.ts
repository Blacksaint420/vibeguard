import { existsSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { collectGitDiff } from "../../core/src/diff.ts";
import { explainRule } from "../../core/src/explain.ts";
import { runCheck } from "../../core/src/engine.ts";
import { DEFAULT_POLICY_TEXT } from "../../core/src/policy.ts";
import { collectRepositoryFiles } from "../../core/src/repository.ts";
import type { Confidence, DiffFile, OutputFormat } from "../../core/src/types.ts";
import { renderFindings } from "../../output/src/formatters.ts";

export type ParsedCommand =
  | { name: "init" }
  | { name: "doctor" }
  | { name: "explain"; id: string }
  | {
      name: "check";
      staged: boolean;
      base?: string;
      targetPath?: string;
      format: OutputFormat;
      quiet: boolean;
      noColor: boolean;
      maxFindings?: number;
      minConfidence?: Confidence;
      vulnProvider: "null" | "mock" | "osv";
    }
  | { name: "help" };

export type CliEnvironment = {
  cwd?: string;
  stdout?: (text: string) => void;
  stderr?: (text: string) => void;
  collectDiff?: (options: { cwd: string; staged?: boolean; base?: string }) => string;
  collectRepositoryFiles?: (targetPath: string) => DiffFile[];
};

export type CliResult = {
  exitCode: 0 | 1 | 2;
};

export function parseArgs(argv: string[]): ParsedCommand {
  const [command = "help", ...rest] = argv;

  if (command === "init") return { name: "init" };
  if (command === "doctor") return { name: "doctor" };
  if (command === "explain") {
    const id = rest[0];
    if (!id) throw new Error("Usage: vibeguard explain <finding_id_or_rule_id>");
    return { name: "explain", id };
  }
  if (command === "check") {
    let staged = false;
    let base: string | undefined;
    let targetPath: string | undefined;
    let format: OutputFormat = "table";
    let quiet = false;
    let noColor = false;
    let maxFindings: number | undefined;
    let minConfidence: Confidence | undefined;
    let vulnProvider: "null" | "mock" | "osv" = "null";

    for (let index = 0; index < rest.length; index += 1) {
      const arg = rest[index];
      if (arg === "--staged") {
        staged = true;
      } else if (arg === "--base") {
        base = rest[index + 1];
        if (!base) throw new Error("Missing value for --base");
        index += 1;
      } else if (arg === "--format") {
        const value = rest[index + 1];
        if (!isOutputFormat(value)) throw new Error("Format must be table, json, sarif, markdown, or html");
        format = value;
        index += 1;
      } else if (arg === "--quiet") {
        quiet = true;
      } else if (arg === "--no-color") {
        noColor = true;
      } else if (arg === "--max-findings") {
        maxFindings = parsePositiveInteger(rest[index + 1], "--max-findings");
        index += 1;
      } else if (arg === "--min-confidence") {
        const value = rest[index + 1];
        if (!isConfidence(value)) throw new Error("Minimum confidence must be low, medium, or high");
        minConfidence = value;
        index += 1;
      } else if (arg === "--vuln-provider") {
        const value = rest[index + 1];
        if (!isVulnProvider(value)) throw new Error("Vulnerability provider must be null, mock, or osv");
        vulnProvider = value;
        index += 1;
      } else if (!arg.startsWith("-") && !targetPath) {
        targetPath = arg;
      } else {
        throw new Error(`Unknown check option: ${arg}`);
      }
    }

    if ((staged || base) && targetPath) {
      throw new Error("A repository path cannot be combined with --staged or --base");
    }

    return { name: "check", staged, base, targetPath, format, quiet, noColor, maxFindings, minConfidence, vulnProvider };
  }

  if (command === "--help" || command === "-h" || command === "help") return { name: "help" };
  throw new Error(`Unknown command: ${command}`);
}

export async function runCli(argv: string[], environment: CliEnvironment = {}): Promise<CliResult> {
  const cwd = environment.cwd ?? process.cwd();
  const stdout = environment.stdout ?? ((text: string) => process.stdout.write(text));
  const stderr = environment.stderr ?? ((text: string) => process.stderr.write(text));

  try {
    const command = parseArgs(argv);

    if (command.name === "help") {
      stdout(helpText());
      return { exitCode: 0 };
    }

    if (command.name === "init") {
      const configPath = join(cwd, "vibeguard.yml");
      if (existsSync(configPath)) {
        stdout("vibeguard.yml already exists.\n");
      } else {
        writeFileSync(configPath, DEFAULT_POLICY_TEXT);
        stdout("Created vibeguard.yml\n");
      }
      return { exitCode: 0 };
    }

    if (command.name === "doctor") {
      stdout(renderDoctor(cwd));
      return { exitCode: 0 };
    }

    if (command.name === "explain") {
      const explanation = explainRule(command.id);
      if (!explanation) {
        stderr(`No explanation found for ${command.id}\n`);
        return { exitCode: 2 };
      }
      stdout(`${explanation}\n`);
      return { exitCode: 0 };
    }

    if (!command.quiet && command.format === "table") {
      stderr(`${command.staged || command.base ? "Scanning git diff" : "Scanning repository"}...\n`);
    }

    const result = command.staged || command.base
      ? await runDiffCheck(command, environment, cwd)
      : await runRepositoryCheck(command, environment, cwd);
    stdout(`${renderFindings(result, command.format)}${command.format === "table" ? "" : "\n"}`);
    return { exitCode: result.summary.blocking > 0 ? 1 : 0 };
  } catch (error) {
    stderr(`${error instanceof Error ? error.message : String(error)}\n`);
    return { exitCode: 2 };
  }
}

function renderDoctor(cwd: string): string {
  const configPath = join(cwd, "vibeguard.yml");
  return [
    "VibeGuard doctor",
    `Node: ${process.version}`,
    `Config: ${existsSync(configPath) ? configPath : "default policy (vibeguard.yml not found)"}`,
    "Mode: local-first",
    "No source upload: enabled",
    "Network vulnerability provider: null/offline",
    ""
  ].join("\n");
}

function helpText(): string {
  return [
    "VibeGuard",
    "",
    "Usage:",
    "  vibeguard init",
    "  vibeguard check [path] [--format table|json|sarif|markdown|html]",
    "  vibeguard check --staged [--format table|json|sarif|markdown|html]",
    "  vibeguard check --base <branch> [--format table|json|sarif|markdown|html]",
    "  vibeguard check [--quiet] [--max-findings <n>] [--min-confidence low|medium|high]",
    "  vibeguard check [--vuln-provider null|mock|osv]",
    "  vibeguard explain <finding_id_or_rule_id>",
    "  vibeguard doctor",
    ""
  ].join("\n");
}

function isOutputFormat(value: string | undefined): value is OutputFormat {
  return value === "table" || value === "json" || value === "sarif" || value === "markdown" || value === "html";
}

async function runDiffCheck(
  command: Extract<ParsedCommand, { name: "check" }>,
  environment: CliEnvironment,
  cwd: string
) {
  const diffText = environment.collectDiff
    ? environment.collectDiff({ cwd, staged: command.staged, base: command.base })
    : collectGitDiff({ cwd, staged: command.staged, base: command.base });
  return runCheck({
    cwd,
    staged: command.staged,
    base: command.base,
    format: command.format,
    diffText,
    maxFindings: command.maxFindings,
    minConfidence: command.minConfidence,
    vulnProvider: command.vulnProvider
  });
}

async function runRepositoryCheck(
  command: Extract<ParsedCommand, { name: "check" }>,
  environment: CliEnvironment,
  cwd: string
) {
  const targetPath = command.targetPath ? resolve(cwd, command.targetPath) : cwd;
  const repositoryFiles = environment.collectRepositoryFiles
    ? environment.collectRepositoryFiles(targetPath)
    : collectRepositoryFiles(targetPath);
  return runCheck({
    cwd,
    targetPath,
    format: command.format,
    repositoryFiles,
    maxFindings: command.maxFindings,
    minConfidence: command.minConfidence,
    vulnProvider: command.vulnProvider
  });
}

function parsePositiveInteger(value: string | undefined, flag: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) throw new Error(`${flag} must be a positive integer`);
  return parsed;
}

function isConfidence(value: string | undefined): value is Confidence {
  return value === "low" || value === "medium" || value === "high";
}

function isVulnProvider(value: string | undefined): value is "null" | "mock" | "osv" {
  return value === "null" || value === "mock" || value === "osv";
}
