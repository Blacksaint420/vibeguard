import type { DiffFile, Finding, VulnerabilityProvider } from "../../core/src/types.ts";
import { scannerFinding } from "./utils.ts";

const LOCKFILES = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock"];
const MANIFESTS = ["package.json", "requirements.txt", "pyproject.toml"];
const SUSPICIOUS_NAMES = new Set(["exprss", "lodahs", "reqeusts", "requets", "djangoo", "flaks", "reactt", "typscript"]);

export const nullVulnerabilityProvider: VulnerabilityProvider = {
  name: "null",
  async query() {
    return [];
  }
};

export function runDependencyScanner(files: DiffFile[]): Finding[] {
  const findings: Finding[] = [];
  const manifestChanged = files.some((file) => isManifest(file.path));
  const lockfileChanged = files.some((file) => isLockfile(file.path));

  for (const file of files) {
    if (isLockfile(file.path)) {
      scanLockfile(file, findings);
    }

    if (!isManifest(file.path)) continue;

    if (file.path.endsWith("package.json")) {
      scanPackageJsonFile(file, findings);
      continue;
    }

    const removedDeps = new Map<string, string>();
    for (const removed of file.removedLines) {
      const parsed = parseDependencyLine(file.path, removed.content);
      if (parsed?.version) removedDeps.set(parsed.name, parsed.version);
    }

    for (const added of file.addedLines) {
      const parsed = parseDependencyLine(file.path, added.content);
      if (!parsed) continue;

      addDependencyFindings(file.path, added.line, added.content, parsed, removedDeps, findings);
    }
  }

  if (lockfileChanged && !manifestChanged) {
    for (const file of files.filter((candidate) => isLockfile(candidate.path))) {
      findings.push(scannerFinding({
        ruleId: "dep-lockfile-without-manifest",
        title: "Lockfile changed without manifest change",
        severity: "medium",
        confidence: "high",
        riskScore: 64,
        file: file.path,
        line: file.addedLines[0]?.line ?? 1,
        snippet: file.addedLines[0]?.content ?? file.path,
        why: "Lockfile-only changes can alter installed code without an obvious manifest review point.",
        suggestedFix: "Explain and review the lockfile delta, or update the manifest in the same change.",
        testSuggestion: "Run a clean install and verify the resolved dependency tree."
      }));
    }
  }

  return findings;
}

function scanLockfile(file: DiffFile, findings: Finding[]): void {
  for (const added of file.addedLines) {
    const trimmed = added.content.trim();
    if (/"hasInstallScript"\s*:\s*true/.test(trimmed) || /\bhasInstallScript:\s*true\b/.test(trimmed)) {
      findings.push(scannerFinding({
        ruleId: "dep-lockfile-install-script",
        title: "Resolved package has install script",
        severity: "high",
        confidence: "high",
        riskScore: 78,
        file: file.path,
        line: added.line,
        snippet: added.content,
        why: "The resolved dependency tree includes a package that can execute code during install.",
        suggestedFix: "Review the package provenance and install script, then remove or pin it only if it is trusted.",
        testSuggestion: "Run a clean install in an isolated CI job and verify no unexpected network or shell commands execute."
      }));
    }

    if (/(resolved\s+|["']resolved["']\s*:\s*["'])http:\/\//i.test(trimmed)) {
      findings.push(scannerFinding({
        ruleId: "dep-lockfile-insecure-resolved-url",
        title: "Lockfile resolves package over HTTP",
        severity: "high",
        confidence: "high",
        riskScore: 82,
        file: file.path,
        line: added.line,
        snippet: added.content,
        why: "HTTP dependency tarball URLs can be intercepted or replaced before installation.",
        suggestedFix: "Regenerate the lockfile using HTTPS registries and verify the configured package registry.",
        testSuggestion: "Run a clean install and confirm resolved URLs use HTTPS."
      }));
    }
  }
}

export async function runVulnerabilityScanner(files: DiffFile[], provider: VulnerabilityProvider): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const dependency of extractDependencies(files)) {
    const vulnerabilities = await provider.query(dependency.name, cleanVersion(dependency.version), dependency.ecosystem);
    for (const vulnerability of vulnerabilities) {
      findings.push(scannerFinding({
        ruleId: "dep-vulnerable-package",
        title: "Vulnerable dependency",
        severity: vulnerability.severity,
        confidence: "high",
        riskScore: vulnerability.severity === "critical" ? 98 : vulnerability.severity === "high" ? 86 : 70,
        file: dependency.file,
        line: dependency.line,
        snippet: `${dependency.name}@${dependency.version}`,
        why: `${vulnerability.id}: ${vulnerability.summary}`,
        suggestedFix: "Upgrade to a non-vulnerable version or remove the dependency.",
        testSuggestion: "Run dependency and integration tests after upgrading the package."
      }));
    }
  }
  return findings.map((finding) => ({ ...finding, scanner: "dependencies" }));
}

export function extractDependencies(files: DiffFile[]): Array<{ name: string; version: string; ecosystem: string; file: string; line: number }> {
  const dependencies: Array<{ name: string; version: string; ecosystem: string; file: string; line: number }> = [];
  for (const file of files) {
    if (!isManifest(file.path)) continue;
    for (const line of file.addedLines) {
      const parsed = file.path.endsWith("package.json")
        ? parsePackageJsonDependencyLine(line.content)
        : parseDependencyLine(file.path, line.content);
      if (!parsed) continue;
      dependencies.push({
        ...parsed,
        ecosystem: file.path.endsWith("requirements.txt") || file.path.endsWith("pyproject.toml") ? "PyPI" : "npm",
        file: file.path,
        line: line.line
      });
    }
  }
  return dependencies;
}

function scanPackageJsonFile(file: DiffFile, findings: Finding[]): void {
  const removedDeps = new Map<string, string>();
  let removedSection = "";
  for (const removed of file.removedLines) {
    removedSection = packageJsonSection(removed.content, removedSection);
    if (!isDependencySection(removedSection)) continue;
    const parsed = parsePackageJsonDependencyLine(removed.content);
    if (parsed?.version) removedDeps.set(parsed.name, parsed.version);
  }

  let addedSection = "";
  for (const added of file.addedLines) {
    addedSection = packageJsonSection(added.content, addedSection);
    if (addedSection === "scripts") {
      addInstallScriptFinding(file.path, added.line, added.content, findings);
    }
    if (!isDependencySection(addedSection)) continue;
    const parsed = parsePackageJsonDependencyLine(added.content);
    if (!parsed) continue;
    addDependencyFindings(file.path, added.line, added.content, parsed, removedDeps, findings);
  }
}

function addInstallScriptFinding(filePath: string, lineNumber: number, lineContent: string, findings: Finding[]): void {
  if (!/"(preinstall|install|postinstall|prepare)"\s*:\s*"[^"]+"/.test(lineContent.trim())) return;
  findings.push(scannerFinding({
    ruleId: "dep-install-script",
    title: "Package lifecycle install script",
    severity: "high",
    confidence: "high",
    riskScore: 78,
    file: filePath,
    line: lineNumber,
    snippet: lineContent,
    why: "Install lifecycle scripts execute during dependency installation and can run arbitrary commands.",
    suggestedFix: "Remove the lifecycle script or replace it with a reviewed build step that does not run during install.",
    testSuggestion: "Run a clean install in CI and verify no unexpected network or shell commands execute."
  }));
}

function addDependencyFindings(
  filePath: string,
  lineNumber: number,
  lineContent: string,
  parsed: { name: string; version: string },
  removedDeps: Map<string, string>,
  findings: Finding[]
): void {
  findings.push(scannerFinding({
    ruleId: "dep-new-or-changed",
    title: "New or changed dependency",
    severity: "low",
    confidence: "medium",
    riskScore: 35,
    file: filePath,
    line: lineNumber,
    snippet: lineContent,
    why: "Dependency changes alter the code that will run in development, CI, or production.",
    suggestedFix: "Review the package name, maintainer, install scripts, changelog, and lockfile delta.",
    testSuggestion: "Run dependency tests and audit the resolved package in the lockfile."
  }));

  if (isBroadOrUnpinned(parsed.version)) {
    findings.push(scannerFinding({
      ruleId: "dep-broad-version-range",
      title: "Broad or unpinned dependency version",
      severity: "medium",
      confidence: "high",
      riskScore: 62,
      file: filePath,
      line: lineNumber,
      snippet: lineContent,
      why: "Broad or unpinned ranges can install unreviewed code later.",
      suggestedFix: "Pin the dependency to an exact reviewed version or tighten the range deliberately.",
      testSuggestion: "Regenerate the lockfile and verify the resolved version is expected."
    }));
  }

  const previous = removedDeps.get(parsed.name);
  if (previous && parsed.version && isVersionDowngrade(previous, parsed.version)) {
    findings.push(scannerFinding({
      ruleId: "dep-version-downgrade",
      title: "Dependency version downgrade",
      severity: "high",
      confidence: "high",
      riskScore: 80,
      file: filePath,
      line: lineNumber,
      snippet: `${parsed.name}: ${previous} -> ${parsed.version}`,
      why: "Downgrades can reintroduce known vulnerabilities or remove security fixes.",
      suggestedFix: "Keep the newer version unless there is a reviewed compatibility reason and vulnerability check.",
      testSuggestion: "Run compatibility tests and verify the downgraded version has no known vulnerabilities."
    }));
  }

  if (SUSPICIOUS_NAMES.has(parsed.name.toLowerCase())) {
    findings.push(scannerFinding({
      ruleId: "dep-suspicious-package-name",
      title: "Suspicious package name",
      severity: "high",
      confidence: "medium",
      riskScore: 74,
      file: filePath,
      line: lineNumber,
      snippet: lineContent,
      why: "The package name resembles common typosquatting patterns.",
      suggestedFix: "Verify the intended package name and package provenance before installing.",
      testSuggestion: "Confirm the lockfile resolves to the expected maintainer and repository."
    }));
  }
}

function parseDependencyLine(path: string, line: string): { name: string; version: string } | undefined {
  const trimmed = line.trim().replace(/,$/, "");
  if (!trimmed || trimmed.startsWith("#")) return undefined;

  if (path.endsWith("requirements.txt")) {
    const match = /^([A-Za-z0-9_.-]+)\s*([=<>!~]{1,2}\s*[A-Za-z0-9*_.-]+)?/.exec(trimmed);
    if (!match) return undefined;
    return { name: match[1], version: (match[2] ?? "").replace(/\s+/g, "") };
  }

  if (path.endsWith("pyproject.toml")) {
    const match = /^([A-Za-z0-9_.-]+)\s*=\s*["']([^"']+)["']/.exec(trimmed)
      ?? /^["']([A-Za-z0-9_.-]+)([=<>!~^ ].*)["']/.exec(trimmed);
    if (!match) return undefined;
    return { name: match[1], version: match[2] ?? "" };
  }

  return undefined;
}

function parsePackageJsonDependencyLine(line: string): { name: string; version: string } | undefined {
  const match = /^"([^"]+)"\s*:\s*"([^"]+)"[,]?$/.exec(line.trim());
  if (!match || !looksLikePackageVersion(match[2])) return undefined;
  return { name: match[1], version: match[2] };
}

function packageJsonSection(line: string, currentSection: string): string {
  const section = /^"([^"]+)"\s*:\s*\{/.exec(line.trim());
  if (section) return section[1];
  if (line.trim() === "}" || line.trim() === "},") return "";
  return currentSection;
}

function isDependencySection(section: string): boolean {
  return ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"].includes(section);
}

function isBroadOrUnpinned(version: string): boolean {
  if (!version) return true;
  return /(^[\^~*]|latest|x|\*|>=|<=|>|<)/i.test(version);
}

function looksLikePackageVersion(version: string): boolean {
  return /^(?:[\^~]?v?\d+\.\d+(?:\.\d+)?|[><=~^*]|latest|workspace:|npm:|file:)/i.test(version);
}

function isVersionDowngrade(previous: string, next: string): boolean {
  const oldParts = cleanVersion(previous).split(".").map(Number);
  const newParts = cleanVersion(next).split(".").map(Number);
  if (oldParts.some(Number.isNaN) || newParts.some(Number.isNaN)) return false;
  for (let index = 0; index < Math.max(oldParts.length, newParts.length); index += 1) {
    const oldPart = oldParts[index] ?? 0;
    const newPart = newParts[index] ?? 0;
    if (newPart < oldPart) return true;
    if (newPart > oldPart) return false;
  }
  return false;
}

function cleanVersion(version: string): string {
  return version.replace(/^[=<>!~^\s]+/, "").replace(/[^0-9.].*$/, "");
}

function isManifest(path: string): boolean {
  return MANIFESTS.some((manifest) => path.endsWith(manifest));
}

function isLockfile(path: string): boolean {
  return LOCKFILES.some((lockfile) => path.endsWith(lockfile));
}
