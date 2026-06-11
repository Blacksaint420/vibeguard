import type { DiffFile, Finding } from "../../core/src/types.ts";
import { scannerFinding } from "./utils.ts";

export function runActionsScanner(files: DiffFile[]): Finding[] {
  const findings: Finding[] = [];

  for (const file of files.filter((candidate) => candidate.path.startsWith(".github/workflows/"))) {
    for (const line of file.addedLines) {
      const uses = /^\s*uses:\s*([^\s#]+)/i.exec(line.content);
      if (uses) {
        const ref = uses[1].split("@")[1];
        if (!ref || !/^[a-f0-9]{40}$/i.test(ref)) {
          findings.push(scannerFinding({
            ruleId: "gha-mutable-action-ref",
            title: "GitHub Action uses mutable reference",
            severity: "high",
            confidence: "high",
            riskScore: 82,
            file: file.path,
            line: line.line,
            snippet: line.content,
            why: "Mutable action references can change CI behavior after review.",
            suggestedFix: "Pin third-party actions to a full commit SHA.",
            testSuggestion: "Run the workflow with the pinned action and verify expected permissions."
          }));
        }
      }

      if (/^\s*permissions:\s*write-all\s*$/i.test(line.content)) {
        findings.push(scannerFinding({
          ruleId: "gha-write-all-permissions",
          title: "GitHub workflow grants write-all permissions",
          severity: "high",
          confidence: "high",
          riskScore: 86,
          file: file.path,
          line: line.line,
          snippet: line.content,
          why: "write-all grants broad repository permissions to every job in the workflow.",
          suggestedFix: "Set the minimum required permissions per workflow or job.",
          testSuggestion: "Run the workflow and confirm jobs still pass with least privilege permissions."
        }));
      }

      if (/pull_request_target/i.test(line.content)) {
        findings.push(scannerFinding({
          ruleId: "gha-pull-request-target",
          title: "pull_request_target workflow trigger",
          severity: "medium",
          confidence: "medium",
          riskScore: 58,
          file: file.path,
          line: line.line,
          snippet: line.content,
          why: "pull_request_target runs with base repository context and can expose secrets if misused.",
          suggestedFix: "Use pull_request unless trusted-code access is required, and never check out untrusted code with secrets.",
          testSuggestion: "Verify forked pull requests cannot access secrets or write tokens."
        }));
      }
    }
  }

  return findings;
}

