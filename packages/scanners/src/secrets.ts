import type { DiffFile, Finding } from "../../core/src/types.ts";
import { owaspCategory } from "../../core/src/owasp.ts";
import { isVendoredOrGeneratedPath, scannerFinding } from "./utils.ts";

type SecretPattern = {
  id: string;
  title: string;
  pattern: RegExp;
  group?: number;
  validate?: (value: string) => boolean;
};

const SECRET_PATTERNS: SecretPattern[] = [
  { id: "secret-private-key", title: "Private key material", pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { id: "secret-aws-access-key", title: "AWS access key", pattern: /\b(AKIA[0-9A-Z]{16})\b/, group: 1 },
  { id: "secret-github-token", title: "GitHub token", pattern: /\b(gh[pousr]_[A-Za-z0-9_]{20,})\b/, group: 1 },
  { id: "secret-slack-token", title: "Slack token", pattern: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/, group: 1 },
  { id: "secret-authorization-header", title: "Authorization header", pattern: /(Authorization\s*[:=]\s*Bearer\s+)([A-Za-z0-9._~+/=-]{12,})/i, group: 2 },
  { id: "pii-us-ssn", title: "US Social Security number", pattern: /\b((?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4})\b/, group: 1 },
  { id: "pii-credit-card", title: "Credit card number", pattern: /\b((?:\d[ -]?){13,19})\b/, group: 1, validate: isValidCreditCardNumber }
];

export function runSecretScanner(files: DiffFile[]): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    if (isVendoredOrGeneratedPath(file.path)) continue;
    for (const line of file.addedLines) {
      for (const secretPattern of SECRET_PATTERNS) {
        const match = secretPattern.pattern.exec(line.content);
        if (!match) continue;
        const matchedValue = secretPattern.group ? match[secretPattern.group] : match[0];
        if (secretPattern.validate && !secretPattern.validate(matchedValue)) continue;
        findings.push(scannerFinding({
          ruleId: secretPattern.id,
          title: secretPattern.title,
          severity: "critical",
          confidence: "high",
          riskScore: 98,
          file: file.path,
          line: line.line,
          snippet: maskSecretsInText(line.content),
          owasp: owaspCategory("LLM02:2025"),
          evidence: "A credential-like value is present in source text.",
          attackPath: "Secret is committed or shown in review output -> unauthorized party copies it -> credential is used outside intended controls.",
          impact: "Exposed credentials can allow account takeover, API abuse, data access, or supply-chain compromise.",
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

function isValidCreditCardNumber(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  if (/^(\d)\1+$/.test(digits)) return false;

  let sum = 0;
  let doubleDigit = false;
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let digit = Number(digits[index]);
    if (doubleDigit) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    doubleDigit = !doubleDigit;
  }
  return sum % 10 === 0;
}
