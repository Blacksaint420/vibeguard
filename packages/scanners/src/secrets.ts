import type { DiffFile, Finding } from "../../core/src/types.ts";
import { scannerFinding } from "./utils.ts";

type SecretPattern = {
  id: string;
  title: string;
  pattern: RegExp;
  group?: number;
};

const SECRET_PATTERNS: SecretPattern[] = [
  { id: "secret-private-key", title: "Private key material", pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { id: "secret-aws-access-key", title: "AWS access key", pattern: /\b(AKIA[0-9A-Z]{16})\b/, group: 1 },
  { id: "secret-github-token", title: "GitHub token", pattern: /\b(gh[pousr]_[A-Za-z0-9_]{20,})\b/, group: 1 },
  { id: "secret-slack-token", title: "Slack token", pattern: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/, group: 1 },
  { id: "secret-authorization-header", title: "Authorization header", pattern: /(Authorization\s*[:=]\s*Bearer\s+)([A-Za-z0-9._~+/=-]{12,})/i, group: 2 },
  { id: "secret-generic-credential", title: "Generic credential assignment", pattern: /\b(api[_-]?key|token|secret|password|passwd|pwd)\b\s*[:=]\s*["']?([A-Za-z0-9_./+=:-]{8,})["']?/i, group: 2 }
];

export function runSecretScanner(files: DiffFile[]): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    for (const line of file.addedLines) {
      for (const secretPattern of SECRET_PATTERNS) {
        const match = secretPattern.pattern.exec(line.content);
        if (!match) continue;
        findings.push(scannerFinding({
          ruleId: secretPattern.id,
          title: secretPattern.title,
          severity: "critical",
          confidence: "high",
          riskScore: 98,
          file: file.path,
          line: line.line,
          snippet: maskSecretsInText(line.content),
          why: "Secrets in source or diffs can be copied from local history, logs, or pull requests.",
          suggestedFix: "Remove the secret, rotate it, and load the value from a secret manager or environment variable.",
          testSuggestion: "Add a config test that fails when required secrets are missing from the environment."
        }));
        break;
      }
    }
  }

  return findings;
}

export function maskSecretsInText(text: string): string {
  let masked = text;
  for (const secretPattern of SECRET_PATTERNS) {
    masked = masked.replace(secretPattern.pattern, (...parts) => {
      const match = parts[0] as string;
      if (!secretPattern.group) return maskSecretValue(match);
      const secret = parts[secretPattern.group] as string;
      return match.replace(secret, maskSecretValue(secret));
    });
  }
  return masked;
}

export function maskSecretValue(value: string): string {
  if (value.length <= 8) return "********";
  return `${value.slice(0, 4)}****${value.slice(-4)}`;
}

