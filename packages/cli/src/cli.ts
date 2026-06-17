import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { baselineFindingIds, createBaseline, DEFAULT_BASELINE_PATH, loadBaseline, serializeBaseline } from "../../core/src/baseline.ts";
import { buildAiBom, buildAgentCapabilityGraph } from "../../core/src/aibom/index.ts";
import { collectGitDiff } from "../../core/src/diff.ts";
import { explainRule } from "../../core/src/explain.ts";
import { runCheck } from "../../core/src/engine.ts";
import {
  DEFAULT_POLICY_TEXT,
  isExpiredSuppressionExpiration,
  isValidSuppressionExpiration,
  loadPolicyFromText
} from "../../core/src/policy.ts";
import { collectRepositoryFiles } from "../../core/src/repository.ts";
import type { Confidence, DiffFile, OutputFormat } from "../../core/src/types.ts";
import { renderFindings } from "../../output/src/formatters.ts";

export type ParsedCommand =
  | { name: "init" }
  | { name: "doctor" }
  | { name: "explain"; id: string }
  | ({ name: "check" } & ScanCommandOptions)
  | ({ name: "report" } & ScanCommandOptions)
  | ({ name: "baseline"; output: string } & ScanCommandOptions)
  | ({ name: "aibom" } & InventoryCommandOptions)
  | ({ name: "graph" } & InventoryCommandOptions)
  | { name: "suppress"; id: string; file?: string; line?: number; reason?: string; reviewer?: string; expires?: string; config?: string }
  | { name: "help" };

type ScanCommandOptions = {
  staged: boolean;
  base?: string;
  targetPath?: string;
  format: OutputFormat;
  quiet: boolean;
  noColor: boolean;
  output?: string;
  baseline?: string;
  maxFindings?: number;
  minConfidence?: Confidence;
  vulnProvider: "null" | "mock" | "osv";
};

type InventoryCommandOptions = {
  targetPath?: string;
  format: OutputFormat;
  output?: string;
};

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
    return { name: "check", ...parseScanOptions(rest, "check", "table") };
  }
  if (command === "report") {
    const options = parseScanOptions(rest, "report", "html");
    return { name: "report", ...options, output: options.output ?? defaultReportPath(options.format) };
  }
  if (command === "baseline") {
    const options = parseScanOptions(rest, "baseline", "json");
    if (options.baseline) throw new Error("baseline cannot be combined with --baseline");
    return { name: "baseline", ...options, output: options.output ?? DEFAULT_BASELINE_PATH };
  }
  if (command === "aibom") {
    return { name: "aibom", ...parseInventoryOptions(rest, "aibom", "aibom-json") };
  }
  if (command === "graph") {
    return { name: "graph", ...parseInventoryOptions(rest, "graph", "graph-json") };
  }
  if (command === "suppress") {
    const id = rest[0];
    if (!id) {
      throw new Error(
        "Usage: vibeguard suppress <finding_id_or_rule_id> [--file <path>] [--line <n>] [--reason <text>] [--reviewer <email>] [--expires <YYYY-MM-DD>]"
      );
    }
    let file: string | undefined;
    let line: number | undefined;
    let reason: string | undefined;
    let reviewer: string | undefined;
    let expires: string | undefined;
    let config: string | undefined;

    for (let index = 1; index < rest.length; index += 1) {
      const arg = rest[index];
      if (arg === "--file") {
        file = requiredValue(rest[index + 1], "--file");
        index += 1;
      } else if (arg === "--line") {
        line = parsePositiveInteger(rest[index + 1], "--line");
        index += 1;
      } else if (arg === "--reason") {
        reason = requiredValue(rest[index + 1], "--reason");
        index += 1;
      } else if (arg === "--reviewer") {
        reviewer = requiredValue(rest[index + 1], "--reviewer");
        index += 1;
      } else if (arg === "--expires") {
        expires = requiredValue(rest[index + 1], "--expires");
        index += 1;
      } else if (arg === "--config") {
        config = requiredValue(rest[index + 1], "--config");
        index += 1;
      } else {
        throw new Error(`Unknown suppress option: ${arg}`);
      }
    }

    return { name: "suppress", id, file, line, reason, reviewer, expires, config };
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

    if (command.name === "suppress") {
      const outputPath = appendSuppression(command, cwd);
      stdout(`Added suppression to ${outputPath}\n`);
      return { exitCode: 0 };
    }

    if (command.name === "aibom" || command.name === "graph") {
      const targetPath = command.targetPath ? resolve(cwd, command.targetPath) : cwd;
      const repositoryFiles = environment.collectRepositoryFiles
        ? environment.collectRepositoryFiles(targetPath)
        : collectRepositoryFiles(targetPath);
      const bom = buildAiBom(repositoryFiles, { targetPath });
      const rendered = command.name === "aibom"
        ? renderFindings({ kind: "aibom", bom } as never, command.format)
        : renderFindings({ kind: "graph", graph: buildAgentCapabilityGraph(bom) } as never, command.format);
      if (command.output) {
        const outputPath = writeOutputFile(cwd, command.output, `${rendered}\n`);
        stdout(`Wrote ${outputPath}\n`);
      } else {
        stdout(`${rendered}\n`);
      }
      return { exitCode: 0 };
    }

    if (!command.quiet && command.format === "table") {
      stderr(`${command.staged || command.base ? "Scanning git diff" : "Scanning repository"}...\n`);
    }

    const result = await runScanCommand(command, environment, cwd);

    if (command.name === "baseline") {
      const outputPath = writeOutputFile(cwd, command.output, serializeBaseline(createBaseline(result)));
      stdout(`Wrote ${outputPath} with ${result.findings.length} findings\n`);
      return { exitCode: 0 };
    }

    const rendered = `${renderFindings(result, command.format)}${command.format === "table" ? "" : "\n"}`;
    if (command.output) {
      const outputPath = writeOutputFile(cwd, command.output, rendered);
      stdout(`Wrote ${outputPath}\n`);
    } else {
      stdout(rendered);
    }
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
    "  vibeguard check [path] [--format table|json|sarif|markdown|html|risk-json]",
    "  vibeguard check --staged [--format table|json|sarif|markdown|html|risk-json]",
    "  vibeguard check --base <branch> [--format table|json|sarif|markdown|html|risk-json]",
    "  vibeguard check [--baseline vibeguard-baseline.json]",
    "  vibeguard check [--output report.json]",
    "  vibeguard check [--quiet] [--max-findings <n>] [--min-confidence low|medium|high]",
    "  vibeguard check [--vuln-provider null|mock|osv]",
    "  vibeguard aibom [path] [--format aibom-json|aibom-markdown] [--output vibeguard-aibom.json]",
    "  vibeguard graph [path] [--format graph-json|graph-markdown] [--output vibeguard-agent-graph.json]",
    "  vibeguard baseline [path] [--output vibeguard-baseline.json]",
    "  vibeguard report [path] [--format json|sarif|markdown|html|risk-json] [--output report.html]",
    "  vibeguard suppress <finding_id_or_rule_id> [--file <path>] [--line <n>] [--reason <text>] [--reviewer <email>] [--expires <YYYY-MM-DD>]",
    "  vibeguard explain <finding_id_or_rule_id>",
    "  vibeguard doctor",
    ""
  ].join("\n");
}

function isOutputFormat(value: string | undefined): value is OutputFormat {
  return value === "table" ||
    value === "json" ||
    value === "sarif" ||
    value === "markdown" ||
    value === "html" ||
    value === "risk-json" ||
    value === "aibom-json" ||
    value === "aibom-markdown" ||
    value === "graph-json" ||
    value === "graph-markdown";
}

async function runDiffCheck(
  command: ScanCommandOptions,
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
    baselineFindingIds: loadBaselineIds(cwd, command.baseline),
    vulnProvider: command.vulnProvider
  });
}

async function runRepositoryCheck(
  command: ScanCommandOptions,
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
    baselineFindingIds: loadBaselineIds(cwd, command.baseline),
    vulnProvider: command.vulnProvider
  });
}

async function runScanCommand(
  command: Extract<ParsedCommand, { name: "check" | "report" | "baseline" }>,
  environment: CliEnvironment,
  cwd: string
) {
  return command.staged || command.base
    ? runDiffCheck(command, environment, cwd)
    : runRepositoryCheck(command, environment, cwd);
}

function parseScanOptions(rest: string[], commandName: string, defaultFormat: OutputFormat): ScanCommandOptions {
  let staged = false;
  let base: string | undefined;
  let targetPath: string | undefined;
  let format: OutputFormat = defaultFormat;
  let quiet = false;
  let noColor = false;
  let output: string | undefined;
  let baseline: string | undefined;
  let maxFindings: number | undefined;
  let minConfidence: Confidence | undefined;
  let vulnProvider: "null" | "mock" | "osv" = "null";

  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === "--staged") {
      staged = true;
    } else if (arg === "--base") {
      base = requiredValue(rest[index + 1], "--base");
      index += 1;
    } else if (arg === "--format") {
      const value = rest[index + 1];
      if (!isOutputFormat(value)) throw new Error("Format must be table, json, sarif, markdown, html, risk-json, aibom-json, aibom-markdown, graph-json, or graph-markdown");
      format = value;
      index += 1;
    } else if (arg === "--quiet") {
      quiet = true;
    } else if (arg === "--no-color") {
      noColor = true;
    } else if (arg === "--output") {
      output = requiredValue(rest[index + 1], "--output");
      index += 1;
    } else if (arg === "--baseline") {
      baseline = requiredValue(rest[index + 1], "--baseline");
      index += 1;
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
      throw new Error(`Unknown ${commandName} option: ${arg}`);
    }
  }

  if ((staged || base) && targetPath) {
    throw new Error("A repository path cannot be combined with --staged or --base");
  }

  return { staged, base, targetPath, format, quiet, noColor, output, baseline, maxFindings, minConfidence, vulnProvider };
}

function parseInventoryOptions(rest: string[], commandName: string, defaultFormat: OutputFormat): InventoryCommandOptions {
  let targetPath: string | undefined;
  let format: OutputFormat = defaultFormat;
  let output: string | undefined;

  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === "--format") {
      const value = rest[index + 1];
      if (!isOutputFormat(value)) throw new Error("Format must be table, json, sarif, markdown, html, risk-json, aibom-json, aibom-markdown, graph-json, or graph-markdown");
      format = value;
      index += 1;
    } else if (arg === "--output") {
      output = requiredValue(rest[index + 1], "--output");
      index += 1;
    } else if (!arg.startsWith("-") && !targetPath) {
      targetPath = arg;
    } else {
      throw new Error(`Unknown ${commandName} option: ${arg}`);
    }
  }

  return { targetPath, format, output };
}

function parsePositiveInteger(value: string | undefined, flag: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) throw new Error(`${flag} must be a positive integer`);
  return parsed;
}

function requiredValue(value: string | undefined, flag: string): string {
  if (!value) throw new Error(`Missing value for ${flag}`);
  return value;
}

function isConfidence(value: string | undefined): value is Confidence {
  return value === "low" || value === "medium" || value === "high";
}

function isVulnProvider(value: string | undefined): value is "null" | "mock" | "osv" {
  return value === "null" || value === "mock" || value === "osv";
}

function loadBaselineIds(cwd: string, baselinePath: string | undefined): string[] | undefined {
  if (!baselinePath) return undefined;
  return baselineFindingIds(loadBaseline(resolve(cwd, baselinePath)));
}

function defaultReportPath(format: OutputFormat): string {
  const extension = format === "markdown" ? "md" : format;
  return `vibeguard-report.${extension}`;
}

function writeOutputFile(cwd: string, outputPath: string, content: string): string {
  const resolvedPath = resolve(cwd, outputPath);
  writeFileSync(resolvedPath, content);
  return outputPath;
}

function appendSuppression(command: Extract<ParsedCommand, { name: "suppress" }>, cwd: string): string {
  const outputPath = command.config ?? "vibeguard.yml";
  const resolvedPath = resolve(cwd, outputPath);
  const existing = existsSync(resolvedPath) ? readFileSync(resolvedPath, "utf8") : DEFAULT_POLICY_TEXT;
  validateSuppressionCommand(command, existing);
  writeFileSync(resolvedPath, addSuppression(existing, command));
  return outputPath;
}

function validateSuppressionCommand(command: Extract<ParsedCommand, { name: "suppress" }>, policyText: string): void {
  const policy = loadPolicyFromText(policyText);
  const missing = [
    policy.suppressionPolicy.requireReason && !command.reason?.trim() ? "reason" : undefined,
    policy.suppressionPolicy.requireReviewer && !command.reviewer?.trim() ? "reviewer" : undefined,
    policy.suppressionPolicy.requireExpiration && !command.expires?.trim() ? "expires" : undefined
  ].filter(Boolean);

  if (missing.length > 0) {
    throw new Error(`Missing required suppression fields: ${missing.join(", ")}`);
  }

  if (command.expires && !isValidSuppressionExpiration(command.expires)) {
    throw new Error("--expires must be a valid YYYY-MM-DD date");
  }

  if (command.expires && isExpiredSuppressionExpiration(command.expires)) {
    throw new Error("--expires must be a future or current YYYY-MM-DD date");
  }
}

function addSuppression(text: string, command: Extract<ParsedCommand, { name: "suppress" }>): string {
  const block = [
    `  - rule: ${yamlScalar(command.id)}`,
    command.file ? `    file: ${yamlScalar(command.file)}` : undefined,
    command.line ? `    line: ${command.line}` : undefined,
    command.reason ? `    reason: ${yamlScalar(command.reason)}` : undefined,
    command.reviewer ? `    reviewer: ${yamlScalar(command.reviewer)}` : undefined,
    command.expires ? `    expires: ${yamlScalar(command.expires)}` : undefined
  ].filter(Boolean).join("\n");

  if (text.includes("suppressions: []")) {
    return text.replace("suppressions: []", `suppressions:\n${block}`);
  }

  if (/\nsuppressions:\s*\n/.test(`\n${text}`)) {
    return `${text.trimEnd()}\n${block}\n`;
  }

  return `${text.trimEnd()}\nsuppressions:\n${block}\n`;
}

function yamlScalar(value: string): string {
  if (/^[A-Za-z0-9_./: -]+$/.test(value) && !value.includes("#")) return value;
  return JSON.stringify(value);
}
