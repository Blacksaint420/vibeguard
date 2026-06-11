import type { DiffFile, Finding, ScannerName } from "../../core/src/types.ts";
import { runActionsScanner } from "./actions.ts";
import { runCodeScanner } from "./code.ts";
import { runDependencyScanner } from "./dependencies.ts";
import { runDockerfileScanner } from "./docker.ts";
import { runSecretScanner } from "./secrets.ts";
import { runSensitiveFileScanner } from "./sensitive-files.ts";

const SCANNERS: Record<ScannerName, (files: DiffFile[]) => Finding[]> = {
  code: runCodeScanner,
  secrets: runSecretScanner,
  dependencies: runDependencyScanner,
  docker: runDockerfileScanner,
  actions: runActionsScanner,
  "sensitive-files": runSensitiveFileScanner
};

export function runScanners(files: DiffFile[], enabledScanners: ScannerName[]): Finding[] {
  return enabledScanners.flatMap((name) => SCANNERS[name]?.(files) ?? []);
}

export {
  runActionsScanner,
  runCodeScanner,
  runDependencyScanner,
  runDockerfileScanner,
  runSecretScanner,
  runSensitiveFileScanner
};

