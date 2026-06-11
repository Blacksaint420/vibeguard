import { collectGitDiff, parseUnifiedDiff } from "./diff.ts";
import { applyPolicy, defaultPolicy, loadPolicy, shouldScanFile } from "./policy.ts";
import type { CheckOptions, CheckResult, DiffFile, Policy } from "./types.ts";
import { runScanners } from "../../scanners/src/index.ts";

export async function runCheck(options: CheckOptions = {}): Promise<CheckResult> {
  const cwd = options.cwd ?? process.cwd();
  const policy = options.policy ?? loadPolicy(cwd);
  const diffText = options.diffText ?? collectGitDiff({ ...options, cwd });
  const files = parseUnifiedDiff(diffText).filter((file) => shouldScanFile(file.path, policy));
  const findings = applyPolicy(runScanners(files, policy.enabledScanners), policy);

  return {
    files,
    findings,
    summary: {
      filesChanged: files.length,
      findings: findings.length,
      blocking: findings.filter((finding) => finding.blocking).length
    }
  };
}

export function runCheckFromDiff(diffText: string, policy: Policy = defaultPolicy()): Promise<CheckResult> {
  return runCheck({ diffText, policy });
}

export type { DiffFile };

