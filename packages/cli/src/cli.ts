import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { createInterface } from "node:readline/promises";

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
import { renderAgentGraphConsole, renderAiBomConsole, renderFindings, renderRiskConsole } from "../../output/src/formatters.ts";

export type ParsedCommand =
  | { name: "interactive"; targetPath?: string }
  | { name: "init" }
  | { name: "setup" }
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
  vulnProviderFailMode: "warn" | "fail";
  vulnProviderTimeoutMs?: number;
  vulnProviderConcurrency?: number;
  strictCoverage: boolean;
  maxFiles?: number;
  maxFileBytes?: number;
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
  prompt?: (question: string) => Promise<string>;
  isTty?: boolean;
  collectDiff?: (options: { cwd: string; staged?: boolean; base?: string }) => string;
  collectRepositoryFiles?: (targetPath: string) => DiffFile[];
};

export type CliResult = {
  exitCode: 0 | 1 | 2;
};

export function parseArgs(argv: string[]): ParsedCommand {
  const [command = "interactive", ...rest] = argv;

  if (command === "interactive" || command === "menu" || command === "framework") {
    return { name: "interactive", ...parseInteractiveOptions(rest, command) };
  }
  if (command === "init") return { name: "init" };
  if (command === "setup" || command === "install" || command === "configure") return { name: "setup" };
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
    return { name: "aibom", ...parseInventoryOptions(rest, "aibom", "table") };
  }
  if (command === "graph") {
    return { name: "graph", ...parseInventoryOptions(rest, "graph", "table") };
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

    if (command.name === "interactive") {
      return runInteractiveFramework(command, environment, cwd, stdout);
    }

    if (command.name === "help") {
      stdout(helpText());
      return { exitCode: 0 };
    }

    if (command.name === "setup") {
      stdout(renderSetupGuide(cwd));
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
    if (command.strictCoverage && result.coverage.coverageStatus !== "complete") {
      stderr(`Coverage incomplete: ${result.coverage.coverageStatus} (${result.coverage.coveragePercent}% scanned)\n`);
      return { exitCode: 2 };
    }

    if (command.name === "baseline") {
      const outputPath = writeOutputFile(cwd, command.output, serializeBaseline(createBaseline(result)));
      stdout(`Wrote ${outputPath} with ${result.findings.length} findings\n`);
      return { exitCode: 0 };
    }

    const rendered = `${renderFindings(result, command.format)}${command.format === "table" ? "" : "\n"}`;
    if (command.output) {
      const outputPath = writeOutputFile(cwd, command.output, rendered);
      stdout(renderWriteSummary(command.name === "report" ? "Report Export" : "Output Export", outputPath, command.format));
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
    "VIBEGUARD / LOCAL RUNTIME CHECK",
    "===============================",
    "VibeGuard doctor",
    "",
    "Runtime",
    "-------",
    `Node: ${process.version}`,
    `Config: ${existsSync(configPath) ? configPath : "default policy (vibeguard.yml not found)"}`,
    "",
    "Privacy Posture",
    "---------------",
    "Mode: local-first",
    "No source upload: enabled",
    "Network vulnerability provider: null/offline",
    "",
    "Operational Guidance",
    "--------------------",
    "- Use --vuln-provider osv only when dependency name/version lookup is approved.",
    "- Use --baseline for accepted legacy findings so new risk is easier to review.",
    ""
  ].join("\n");
}

function renderSetupGuide(cwd: string): string {
  const configPath = join(cwd, "vibeguard.yml");
  return [
    "VIBEGUARD / SETUP GUIDE",
    "=======================",
    "Use this guide when installing VibeGuard or preparing a repository for local scanning.",
    "",
    "Required Runtime",
    "----------------",
    "- Node.js 20+",
    "- npm 10+ recommended",
    "- Git is recommended for diff, staged, baseline, and CI workflows",
    "",
    "Install",
    "-------",
    "From a local source checkout:",
    "  npm install",
    "  npm run build",
    "  npm run vibeguard -- doctor",
    "",
    "From npm after the package is published:",
    "  npm install -g vibeguard",
    "  vibeguard doctor",
    "",
    "Repository Setup",
    "----------------",
    `Current target: ${cwd}`,
    `Config file: ${existsSync(configPath) ? configPath : "not found yet"}`,
    "  vibeguard init",
    "  vibeguard doctor",
    "  vibeguard check --format table",
    "  vibeguard report --format html --output vibeguard-report.html",
    "",
    "API Keys And Credentials",
    "------------------------",
    "- No OpenAI, Anthropic, Gemini, or LLM provider API key is required by VibeGuard.",
    "- Configure your own application API keys in your app runtime environment or secret manager, not in VibeGuard config.",
    "- Common app-owned examples include OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY, and provider-specific service credentials.",
    "- VibeGuard scans local files and should never be used as a secret store.",
    "- NPM_TOKEN is only needed by maintainers when publishing the package; it is not required to scan an application.",
    "",
    "Optional Dependency Vulnerability Intelligence",
    "----------------------------------------------",
    "- Local scanning is offline by default.",
    "- LLM03 dependency vulnerability checks can call OSV when explicitly enabled:",
    "  vibeguard check --vuln-provider osv",
    "- OSV lookup sends package names, versions, and ecosystems only; it does not upload source code.",
    "- OSV does not require an API key.",
    "- For strict CI, choose the network failure behavior explicitly:",
    "  vibeguard check --vuln-provider osv --vuln-provider-fail-mode warn",
    "  vibeguard check --vuln-provider osv --vuln-provider-fail-mode fail",
    "",
    "Useful Configuration",
    "--------------------",
    "- vibeguard.yml controls policy, severities, blocking behavior, suppressions, and report mapping.",
    "- VIBEGUARD_TARGET can set the default target for interactive mode.",
    "- Use --baseline vibeguard-baseline.json for accepted legacy findings.",
    "- Use --output for JSON, SARIF, Markdown, HTML, AI BOM, graph, and risk exports.",
    "",
    "Verify Setup",
    "------------",
    "  vibeguard doctor",
    "  vibeguard check --format table",
    "  vibeguard aibom --format table",
    "  vibeguard graph --format table",
    ""
  ].join("\n");
}

function renderWriteSummary(moduleName: string, outputPath: string, format: OutputFormat): string {
  return [
    `VIBEGUARD / ${moduleName.toUpperCase()}`,
    "=".repeat(`VIBEGUARD / ${moduleName.toUpperCase()}`.length),
    `Status: written`,
    `Format: ${format}`,
    `Path: ${outputPath}`,
    `Wrote ${outputPath}`,
    ""
  ].join("\n");
}

function helpText(): string {
  return [
    "VibeGuard",
    "",
    "Usage:",
    "  vibeguard",
    "  vibeguard interactive [--target <path>]",
    "  vibeguard init",
    "  vibeguard setup",
    "  vibeguard check [path] [--format table|json|sarif|markdown|html|risk-json]",
    "  vibeguard check --staged [--format table|json|sarif|markdown|html|risk-json]",
    "  vibeguard check --base <branch> [--format table|json|sarif|markdown|html|risk-json]",
    "  vibeguard check [--baseline vibeguard-baseline.json]",
    "  vibeguard check [--output report.json]",
    "  vibeguard check [--quiet] [--max-findings <n>] [--min-confidence low|medium|high]",
    "  vibeguard check [--vuln-provider null|mock|osv]",
    "  vibeguard aibom [path] [--format table|aibom-json|aibom-markdown] [--output vibeguard-aibom.json]",
    "  vibeguard graph [path] [--format table|graph-json|graph-markdown] [--output vibeguard-agent-graph.json]",
    "  vibeguard baseline [path] [--output vibeguard-baseline.json]",
    "  vibeguard report [path] [--format json|sarif|markdown|html|risk-json] [--output report.html]",
    "  vibeguard suppress <finding_id_or_rule_id> [--file <path>] [--line <n>] [--reason <text>] [--reviewer <email>] [--expires <YYYY-MM-DD>]",
    "  vibeguard explain <finding_id_or_rule_id>",
    "  vibeguard doctor",
    "",
    "Setup aliases:",
    "  vibeguard install",
    "  vibeguard configure",
    ""
  ].join("\n");
}

async function runInteractiveFramework(
  command: Extract<ParsedCommand, { name: "interactive" }>,
  environment: CliEnvironment,
  cwd: string,
  stdout: (text: string) => void
): Promise<CliResult> {
  const canPrompt = environment.prompt ? true : environment.isTty ?? Boolean(process.stdin.isTTY);
  const defaultTarget = resolve(cwd, command.targetPath ?? process.env.VIBEGUARD_TARGET ?? cwd);

  if (!canPrompt) {
    stdout([
      frameworkHeader(),
      "Interactive mode needs a terminal input stream.",
      "",
      "Run one of these commands instead:",
      `  vibeguard interactive --target "${defaultTarget}"`,
      `  vibeguard check "${defaultTarget}" --format table`,
      `  vibeguard aibom "${defaultTarget}" --format aibom-markdown`,
      "",
      helpText()
    ].join("\n"));
    return { exitCode: 0 };
  }

  const readline = environment.prompt
    ? undefined
    : createInterface({ input: process.stdin, output: process.stdout });
  const ask = environment.prompt ?? ((question: string) => readline!.question(question));
  let finalExitCode: 0 | 1 = 0;

  try {
    stdout(`${frameworkHeader()}\n`);
    stdout("Type help for commands, set-target to change scope, or exit to quit.\n\n");
    let currentTarget = await chooseInteractiveTarget(defaultTarget, cwd, ask);

    while (true) {
      stdout(interactiveMenu(currentTarget));
      const choice = normalizeChoice(await ask("vibeguard > "), "help");
      const action = interactiveAction(choice);
      if (action === "exit") {
        stdout("Exiting VibeGuard.\n");
        return { exitCode: finalExitCode };
      }

      if (action === "help") {
        continue;
      }

      if (action === "target") {
        currentTarget = await chooseInteractiveTarget(currentTarget, cwd, ask);
        stdout(`Target set to ${currentTarget}\n`);
        continue;
      }

      if (action === "scan") {
        const scopePath = await chooseInteractiveScope(currentTarget, cwd, ask);
        const minConfidence = await chooseInteractiveConfidence(ask);
        const maxFindings = await chooseMaxFindings(ask);
        stdout(renderRunIntent("Developer security scan", scopePath, [
          "Runs code, secret, dependency, Docker, workflow, sensitive-file, and AI rules.",
          "Blocks only findings that match the active policy."
        ]));
        const result = await runInteractiveCheck(scopePath, environment, cwd, { format: "table", minConfidence, maxFindings });
        stdout(renderFindings(result, "table"));
        if (result.summary.blocking > 0) finalExitCode = 1;
      } else if (action === "risk") {
        const scopePath = await chooseInteractiveScope(currentTarget, cwd, ask);
        const maxFindings = await chooseMaxFindings(ask);
        stdout(renderRunIntent("GRC risk briefing", scopePath, [
          "Groups technical findings into risk categories and framework mappings.",
          "Use risk-json when you need machine-readable evidence for GRC workflows."
        ]));
        const result = await runInteractiveCheck(scopePath, environment, cwd, { format: "markdown", maxFindings });
        stdout(renderRiskConsole(result));
        if (result.summary.blocking > 0) finalExitCode = 1;
      } else if (action === "aibom") {
        const scopePath = await chooseInteractiveScope(currentTarget, cwd, ask);
        stdout(renderRunIntent("AI Bill of Materials", scopePath, [
          "Inventories AI providers, models, prompts, agents, tools, vector stores, MCP servers, and data stores.",
          "Use this to understand what AI assets exist before reviewing risk."
        ]));
        const bom = buildAiBom(collectInteractiveFiles(scopePath, environment), { targetPath: scopePath });
        stdout(`${renderAiBomConsole(bom)}\n`);
      } else if (action === "graph") {
        const scopePath = await chooseInteractiveScope(currentTarget, cwd, ask);
        stdout(renderRunIntent("Agent capability graph", scopePath, [
          "Builds an asset graph from AI BOM data and highlights high-risk capability paths.",
          "Useful for excessive agency, shell access, filesystem access, database access, and secret access review."
        ]));
        const bom = buildAiBom(collectInteractiveFiles(scopePath, environment), { targetPath: scopePath });
        stdout(`${renderAgentGraphConsole(buildAgentCapabilityGraph(bom))}\n`);
      } else if (action === "full") {
        const scopePath = await chooseInteractiveScope(currentTarget, cwd, ask);
        const maxFindings = await chooseMaxFindings(ask);
        stdout(renderRunIntent("Full VibeGuard review", scopePath, [
          "Runs the security scan, AI BOM, and agent capability graph together.",
          "This is the best single option when you are testing the framework manually."
        ]));
        const result = await runInteractiveCheck(scopePath, environment, cwd, { format: "table", maxFindings });
        stdout(renderFindings(result, "table"));
        stdout(`${renderAiBomConsole(result.aiBom!)}\n`);
        stdout(`${renderAgentGraphConsole(result.agentGraph!)}\n`);
        if (result.summary.blocking > 0) finalExitCode = 1;
      } else if (action === "report") {
        const scopePath = await chooseInteractiveScope(currentTarget, cwd, ask);
        const outputPath = normalizeChoice(await ask("Report output path [vibeguard-report.html]: "), "vibeguard-report.html");
        stdout(renderRunIntent("HTML report", scopePath, [
          "Writes a shareable report with findings, next actions, OWASP mapping, and GRC mapping."
        ]));
        const result = await runInteractiveCheck(scopePath, environment, cwd, { format: "html" });
        const written = writeOutputFile(cwd, outputPath, renderFindings(result, "html"));
        stdout(renderWriteSummary("Report Export", written, "html"));
        if (result.summary.blocking > 0) finalExitCode = 1;
      } else if (action === "explain") {
        const ruleId = normalizeChoice(await ask("Rule ID to explain [ai-model-trust-remote-code]: "), "ai-model-trust-remote-code");
        const explanation = explainRule(ruleId);
        stdout(explanation ? `${explanation}\n` : `No explanation found for ${ruleId}\n`);
      } else if (action === "setup") {
        stdout(renderSetupGuide(cwd));
      } else if (action === "doctor") {
        stdout(renderDoctor(cwd));
      } else {
        stdout(`Unknown option: ${choice}\n`);
      }
    }
  } finally {
    readline?.close();
  }
}

function frameworkHeader(): string {
  return [
    "VIBEGUARD / COMMAND CENTER",
    "==========================",
    "VibeGuard Framework",
    "AI security CLI framework for developer, security, and GRC workflows."
  ].join("\n");
}

function interactiveMenu(defaultTarget: string): string {
  return [
    "Session",
    "-------",
    `Target: ${truncateMiddle(defaultTarget, 72)}`,
    "",
    "Modules",
    "-------",
    "1  scan        Security scan: findings, merge decision, fixes",
    "2  risk        GRC risk brief: categories, controls, frameworks",
    "3  aibom       AI inventory: providers, models, prompts, tools",
    "4  graph       Agent access graph: reachable capabilities",
    "5  full        Full review: scan + AI BOM + graph",
    "6  report      HTML report export",
    "7  explain     Rule brief and framework mappings",
    "8  doctor      Local runtime and privacy posture",
    "   setup       Installation, API key, and configuration guide",
    "0  set-target  Change application target",
    "9  exit        Quit",
    ""
  ].join("\n");
}

function interactiveAction(choice: string): string {
  const normalized = choice.trim().toLowerCase();
  const aliases: Record<string, string> = {
    "0": "target",
    "set-target": "target",
    target: "target",
    use: "target",
    "1": "scan",
    scan: "scan",
    check: "scan",
    "2": "risk",
    risk: "risk",
    grc: "risk",
    "3": "aibom",
    aibom: "aibom",
    bom: "aibom",
    "4": "graph",
    graph: "graph",
    "5": "full",
    full: "full",
    review: "full",
    "6": "report",
    report: "report",
    "7": "explain",
    explain: "explain",
    "8": "doctor",
    doctor: "doctor",
    setup: "setup",
    install: "setup",
    configure: "setup",
    "9": "exit",
    exit: "exit",
    quit: "exit",
    q: "exit",
    help: "help",
    "?": "help"
  };
  return aliases[normalized] ?? normalized;
}

function truncateMiddle(value: string, maxLength: number): string {
  if (value.length <= maxLength) return value;
  const half = Math.floor((maxLength - 3) / 2);
  return `${value.slice(0, half)}...${value.slice(value.length - (maxLength - 3 - half))}`;
}

function renderRunIntent(title: string, targetPath: string, details: string[]): string {
  return [
    "",
    `VIBEGUARD / ${title.toUpperCase()}`,
    "=".repeat(`VIBEGUARD / ${title.toUpperCase()}`.length),
    `Target: ${targetPath}`,
    "",
    "Run Plan",
    "--------",
    ...details.map((detail) => `- ${detail}`),
    ""
  ].join("\n");
}

async function chooseInteractiveTarget(
  defaultTarget: string,
  cwd: string,
  ask: (question: string) => Promise<string>
): Promise<string> {
  const answer = normalizeChoice(await ask(`Target path [${defaultTarget}]: `), defaultTarget);
  return resolve(cwd, answer);
}

async function chooseInteractiveScope(
  targetPath: string,
  cwd: string,
  ask: (question: string) => Promise<string>
): Promise<string> {
  const srcPath = join(targetPath, "src");
  const serverPath = join(targetPath, "server");
  const defaultScope = existsSync(srcPath) ? "1" : "3";
  const choice = normalizeChoice(await ask([
    "Scope:",
    existsSync(srcPath) ? `  1. App source (${srcPath})` : "  1. App source (not found, falls back to target)",
    existsSync(serverPath) ? `  2. Server (${serverPath})` : "  2. Server (not found, falls back to target)",
    `  3. Full target (${targetPath})`,
    "  4. Custom path",
    `Select scope [${defaultScope}]: `
  ].join("\n")), defaultScope);

  if (choice === "1") return existsSync(srcPath) ? srcPath : targetPath;
  if (choice === "2") return existsSync(serverPath) ? serverPath : targetPath;
  if (choice === "4") return resolve(cwd, normalizeChoice(await ask("Custom path: "), targetPath));
  return targetPath;
}

async function chooseInteractiveConfidence(ask: (question: string) => Promise<string>): Promise<Confidence | undefined> {
  const choice = normalizeChoice(await ask("Minimum confidence: 1=high 2=medium 3=low [1]: "), "1");
  if (choice === "2" || choice.toLowerCase() === "medium") return "medium";
  if (choice === "3" || choice.toLowerCase() === "low") return "low";
  return "high";
}

async function chooseMaxFindings(ask: (question: string) => Promise<string>): Promise<number> {
  const value = normalizeChoice(await ask("Max findings to display [25]: "), "25");
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : 25;
}

function normalizeChoice(value: string, fallback: string): string {
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : fallback;
}

function collectInteractiveFiles(targetPath: string, environment: CliEnvironment): DiffFile[] {
  return environment.collectRepositoryFiles
    ? environment.collectRepositoryFiles(targetPath)
    : collectRepositoryFiles(targetPath);
}

async function runInteractiveCheck(
  targetPath: string,
  environment: CliEnvironment,
  cwd: string,
  options: Pick<ScanCommandOptions, "format" | "maxFindings" | "minConfidence">
) {
  const repositoryFiles = collectInteractiveFiles(targetPath, environment);
  return runCheck({
    cwd,
    targetPath,
    repositoryFiles,
    format: options.format,
    maxFindings: options.maxFindings,
    minConfidence: options.minConfidence,
    strictCoverage: false,
    vulnProvider: "null",
    vulnProviderFailMode: "warn"
  });
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
    vulnProvider: command.vulnProvider,
    vulnProviderFailMode: command.vulnProviderFailMode,
    vulnProviderTimeoutMs: command.vulnProviderTimeoutMs,
    vulnProviderConcurrency: command.vulnProviderConcurrency,
    maxFiles: command.maxFiles,
    maxFileBytes: command.maxFileBytes
  });
}

async function runRepositoryCheck(
  command: ScanCommandOptions,
  environment: CliEnvironment,
  cwd: string
) {
  const targetPath = command.targetPath ? resolve(cwd, command.targetPath) : cwd;
  const repositoryFiles = environment.collectRepositoryFiles ? environment.collectRepositoryFiles(targetPath) : undefined;
  return runCheck({
    cwd,
    targetPath,
    format: command.format,
    repositoryFiles,
    maxFindings: command.maxFindings,
    minConfidence: command.minConfidence,
    baselineFindingIds: loadBaselineIds(cwd, command.baseline),
    vulnProvider: command.vulnProvider,
    vulnProviderFailMode: command.vulnProviderFailMode,
    vulnProviderTimeoutMs: command.vulnProviderTimeoutMs,
    vulnProviderConcurrency: command.vulnProviderConcurrency,
    maxFiles: command.maxFiles,
    maxFileBytes: command.maxFileBytes
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

function parseInteractiveOptions(rest: string[], commandName: string): { targetPath?: string } {
  let targetPath: string | undefined;

  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === "--target") {
      targetPath = requiredValue(rest[index + 1], "--target");
      index += 1;
    } else if (!arg.startsWith("-") && !targetPath) {
      targetPath = arg;
    } else {
      throw new Error(`Unknown ${commandName} option: ${arg}`);
    }
  }

  return { targetPath };
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
  let vulnProviderFailMode: "warn" | "fail" = "warn";
  let vulnProviderTimeoutMs: number | undefined;
  let vulnProviderConcurrency: number | undefined;
  let strictCoverage = false;
  let maxFiles: number | undefined;
  let maxFileBytes: number | undefined;

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
    } else if (arg === "--vuln-provider-fail-mode") {
      const value = rest[index + 1];
      if (value !== "warn" && value !== "fail") throw new Error("Vulnerability provider fail mode must be warn or fail");
      vulnProviderFailMode = value;
      index += 1;
    } else if (arg === "--vuln-provider-timeout-ms") {
      vulnProviderTimeoutMs = parsePositiveInteger(rest[index + 1], "--vuln-provider-timeout-ms");
      index += 1;
    } else if (arg === "--vuln-provider-concurrency") {
      vulnProviderConcurrency = parsePositiveInteger(rest[index + 1], "--vuln-provider-concurrency");
      index += 1;
    } else if (arg === "--strict-coverage") {
      strictCoverage = true;
    } else if (arg === "--max-files") {
      maxFiles = parsePositiveInteger(rest[index + 1], "--max-files");
      index += 1;
    } else if (arg === "--max-file-bytes") {
      maxFileBytes = parsePositiveInteger(rest[index + 1], "--max-file-bytes");
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

  return {
    staged,
    base,
    targetPath,
    format,
    quiet,
    noColor,
    output,
    baseline,
    maxFindings,
    minConfidence,
    vulnProvider,
    vulnProviderFailMode,
    vulnProviderTimeoutMs,
    vulnProviderConcurrency,
    strictCoverage,
    maxFiles,
    maxFileBytes
  };
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
  return baselineFindingIds(loadBaseline(resolveCwdPath(cwd, baselinePath, "--baseline")));
}

function defaultReportPath(format: OutputFormat): string {
  const extension = format === "markdown" ? "md" : format;
  return `vibeguard-report.${extension}`;
}

function writeOutputFile(cwd: string, outputPath: string, content: string): string {
  const resolvedPath = resolveCwdPath(cwd, outputPath, "--output");
  mkdirSync(dirname(resolvedPath), { recursive: true });
  writeFileSync(resolvedPath, content);
  return outputPath;
}

function appendSuppression(command: Extract<ParsedCommand, { name: "suppress" }>, cwd: string): string {
  const outputPath = command.config ?? "vibeguard.yml";
  const resolvedPath = resolveCwdPath(cwd, outputPath, "--config");
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

function resolveCwdPath(cwd: string, requestedPath: string, flag: string): string {
  const root = resolve(cwd);
  const resolvedPath = resolve(root, requestedPath);
  if (!isPathInside(root, resolvedPath)) {
    throw new Error(`${flag} must stay inside the working directory`);
  }
  return resolvedPath;
}

function isPathInside(root: string, path: string): boolean {
  const candidate = relative(root, path);
  return candidate === "" || (!candidate.startsWith("..") && !isAbsolute(candidate));
}
