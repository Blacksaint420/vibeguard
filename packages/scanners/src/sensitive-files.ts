import type { DiffFile, Finding } from "../../core/src/types.ts";
import { scannerFinding } from "./utils.ts";

const SENSITIVE_PATTERNS = [
  /(^|\/)\.env(\.|$)?/,
  /(^|\/)\.npmrc$/,
  /(^|\/)\.pypirc$/,
  /(^|\/)id_rsa$/,
  /(^|\/)id_ed25519$/,
  /\.pem$/,
  /\.key$/,
  /(^|\/)\.aws\/credentials$/,
  /(^|\/)\.kube\/config$/,
  /(^|\/)credentials\.json$/
];

export function runSensitiveFileScanner(files: DiffFile[]): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    if (!SENSITIVE_PATTERNS.some((pattern) => pattern.test(file.path))) continue;
    findings.push(scannerFinding({
      ruleId: "sensitive-file-change",
      title: "Sensitive file changed",
      severity: "high",
      confidence: "medium",
      riskScore: 84,
      file: file.path,
      line: file.addedLines[0]?.line ?? 1,
      snippet: file.addedLines[0]?.content ?? file.path,
      evidence: `Sensitive path changed: ${file.path}.`,
      attackPath: "Sensitive file enters source tree -> credentials or private data become available in history, reviews, or artifacts.",
      impact: "Exposed sensitive files can disclose API keys, environment secrets, cloud credentials, or private identities.",
      why: "Sensitive files often contain credentials, machine identities, or private environment data.",
      suggestedFix: "Remove the file from the diff, rotate any exposed credentials, and use secret storage.",
      testSuggestion: "Add ignore rules and a secret-scanning test or pre-commit check for this path."
    }));
  }

  return findings;
}
