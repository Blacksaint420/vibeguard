import { collectGitDiff, parseUnifiedDiff } from "./diff.ts";
import { applyPolicy, defaultPolicy, loadPolicy, shouldScanFile } from "./policy.ts";
import { collectRepositoryFiles } from "./repository.ts";
import type { CheckOptions, CheckResult, DiffFile, Policy } from "./types.ts";
import { runScanners } from "../../scanners/src/index.ts";

export async function runCheck(options: CheckOptions = {}): Promise<CheckResult> {
  const cwd = options.cwd ?? process.cwd();
  const policy = options.policy ?? loadPolicy(cwd);
  const files = collectFilesForCheck(options, cwd, policy);
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

function collectFilesForCheck(options: CheckOptions, cwd: string, policy: Policy): DiffFile[] {
  if (options.repositoryFiles) {
    return options.repositoryFiles.filter((file) => shouldScanFile(file.path, policy));
  }

  if (options.diffText || options.staged || options.base) {
    const diffText = options.diffText ?? collectGitDiff({ ...options, cwd });
    return parseUnifiedDiff(diffText).filter((file) => shouldScanFile(file.path, policy));
  }

  const targetPath = options.targetPath ?? cwd;
  return collectRepositoryFiles(targetPath).filter((file) => shouldScanFile(file.path, policy));
}
