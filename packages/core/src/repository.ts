import { readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";

import type { CoverageSummary, DiffFile, ScanWarning, ScanWarningCode } from "./types.ts";

const MAX_REPOSITORY_FILES = 10_000;
const MAX_TEXT_FILE_BYTES = 1024 * 1024;

export type RepositoryCollectionOptions = {
  maxFiles?: number;
  maxFileBytes?: number;
};

export type RepositoryCollection = {
  files: DiffFile[];
  warnings: ScanWarning[];
  coverage: CoverageSummary;
  durationMs: number;
};

type CollectionState = {
  rootRealPath: string;
  maxFiles: number;
  maxFileBytes: number;
  filesDiscovered: number;
  filesScanned: number;
  filesSkippedBinary: number;
  filesSkippedOversized: number;
  filesUnreadable: number;
  fileLimitReached: boolean;
};

export function collectRepository(rootPath: string, options: RepositoryCollectionOptions = {}): RepositoryCollection {
  const started = Date.now();
  const warnings: ScanWarning[] = [];
  const root = resolve(rootPath);
  const state = initialState(options);

  try {
    const stat = statSync(root);
    if (stat.isFile()) {
      state.filesDiscovered += 1;
      const file = fileToDiffFile(root, root, stat, state, warnings);
      const files = file ? [file] : [];
      return { files, warnings, coverage: buildCoverage(state, files.length, 0), durationMs: Date.now() - started };
    }

    const rootRealPath = realpathSync(root);
    state.rootRealPath = rootRealPath;
    const files = walkDirectory(root, root, new Set([rootRealPath]), state, warnings)
      .sort((left, right) => left.path.localeCompare(right.path));
    return { files, warnings, coverage: buildCoverage(state, files.length, 0), durationMs: Date.now() - started };
  } catch (error) {
    state.filesUnreadable += 1;
    warnings.push(warning("unreadable", rootPath, errorMessage(error)));
    return { files: [], warnings, coverage: buildCoverage(state, 0, 0), durationMs: Date.now() - started };
  }
}

export function collectRepositoryFiles(rootPath: string): DiffFile[] {
  return collectRepository(rootPath).files;
}

function walkDirectory(
  root: string,
  directory: string,
  ancestors: Set<string>,
  state: CollectionState,
  warnings: ScanWarning[]
): DiffFile[] {
  const files: DiffFile[] = [];

  let entries;
  try {
    entries = readdirSync(directory, { withFileTypes: true });
  } catch (error) {
    state.filesUnreadable += 1;
    warnings.push(warning("unreadable", toRepositoryPath(relative(root, directory) || directory), errorMessage(error)));
    return files;
  }

  for (const entry of entries) {
    const fullPath = resolve(directory, entry.name);
    const repositoryPath = toRepositoryPath(relative(root, fullPath) || fullPath);
    let realPath;
    try {
      realPath = realpathSync(fullPath);
    } catch (error) {
      state.filesUnreadable += 1;
      warnings.push(warning("unreadable", repositoryPath, errorMessage(error)));
      continue;
    }

    if (!isPathInside(state.rootRealPath, realPath)) {
      warnings.push(warning("outside-root", repositoryPath, "Skipped path outside target root."));
      continue;
    }

    let stat;
    try {
      stat = statSync(fullPath);
    } catch (error) {
      state.filesUnreadable += 1;
      warnings.push(warning("unreadable", repositoryPath, errorMessage(error)));
      continue;
    }

    if (stat.isDirectory()) {
      if (ancestors.has(realPath)) continue;
      files.push(...walkDirectory(root, fullPath, new Set([...ancestors, realPath]), state, warnings));
      continue;
    }

    if (stat.isFile()) {
      state.filesDiscovered += 1;
      if (state.filesScanned >= state.maxFiles) {
        recordFileLimitWarning(state, warnings);
        break;
      }
      const file = fileToDiffFile(root, fullPath, stat, state, warnings);
      if (file) files.push(file);
    }
  }

  return files;
}

function fileToDiffFile(
  root: string,
  fullPath: string,
  stat: ReturnType<typeof statSync>,
  state: CollectionState,
  warnings: ScanWarning[]
): DiffFile | undefined {
  const path = toRepositoryPath(relative(root, fullPath) || fullPath);
  if (stat.size > state.maxFileBytes) {
    state.filesSkippedOversized += 1;
    warnings.push(warning("oversized", path, `Skipped file larger than ${state.maxFileBytes} bytes.`));
    return undefined;
  }

  let contentBuffer;
  try {
    contentBuffer = readFileSync(fullPath);
  } catch (error) {
    state.filesUnreadable += 1;
    warnings.push(warning("unreadable", path, errorMessage(error)));
    return undefined;
  }

  if (contentBuffer.includes(0)) {
    state.filesSkippedBinary += 1;
    warnings.push(warning("binary", path, "Skipped binary file."));
    return undefined;
  }

  const content = contentBuffer.toString("utf8");
  const lines = content.split(/\r?\n/);
  if (lines.at(-1) === "") lines.pop();

  const allLines = lines.map((line, index) => ({ line: index + 1, content: line }));

  state.filesScanned += 1;

  return {
    path,
    oldPath: path,
    status: "modified",
    addedLines: allLines,
    removedLines: [],
    allLines
  };
}

function recordFileLimitWarning(state: CollectionState, warnings: ScanWarning[]): void {
  if (state.fileLimitReached) return;
  state.fileLimitReached = true;
  warnings.push(warning("file-limit", ".", `Stopped repository collection after ${state.maxFiles} files. Narrow the target path or exclude generated directories.`));
}

function initialState(options: RepositoryCollectionOptions): CollectionState {
  return {
    rootRealPath: "",
    maxFiles: options.maxFiles ?? MAX_REPOSITORY_FILES,
    maxFileBytes: options.maxFileBytes ?? MAX_TEXT_FILE_BYTES,
    filesDiscovered: 0,
    filesScanned: 0,
    filesSkippedBinary: 0,
    filesSkippedOversized: 0,
    filesUnreadable: 0,
    fileLimitReached: false
  };
}

function buildCoverage(state: CollectionState, filesScanned: number, filesExcludedByPolicy: number): CoverageSummary {
  const filesSkipped = state.filesSkippedBinary + state.filesSkippedOversized + state.filesUnreadable + (state.fileLimitReached ? 1 : 0);
  const denominator = filesScanned + filesSkipped + filesExcludedByPolicy;
  const coveragePercent = denominator === 0 ? 100 : Math.round((filesScanned / denominator) * 10000) / 100;
  const coverageStatus = state.filesUnreadable > 0 && filesScanned === 0
    ? "failed"
    : filesSkipped > 0 || filesExcludedByPolicy > 0 || state.fileLimitReached
      ? "partial"
      : "complete";

  return {
    filesDiscovered: state.filesDiscovered,
    filesScanned,
    filesSkipped,
    filesExcludedByPolicy,
    filesSkippedBinary: state.filesSkippedBinary,
    filesSkippedOversized: state.filesSkippedOversized,
    filesUnreadable: state.filesUnreadable,
    fileLimitReached: state.fileLimitReached,
    coveragePercent,
    coverageStatus
  };
}

export function applyPolicyCoverage(collection: RepositoryCollection, filesScanned: number, filesExcludedByPolicy: number): CoverageSummary {
  return {
    ...collection.coverage,
    filesScanned,
    filesExcludedByPolicy,
    filesSkipped: collection.coverage.filesSkipped,
    coveragePercent: coveragePercent(filesScanned, collection.coverage.filesSkipped, filesExcludedByPolicy),
    coverageStatus: collection.coverage.coverageStatus === "failed"
      ? "failed"
      : collection.coverage.filesSkipped > 0 || filesExcludedByPolicy > 0
        ? "partial"
        : "complete"
  };
}

function coveragePercent(filesScanned: number, filesSkipped: number, filesExcludedByPolicy: number): number {
  const denominator = filesScanned + filesSkipped + filesExcludedByPolicy;
  return denominator === 0 ? 100 : Math.round((filesScanned / denominator) * 10000) / 100;
}

function warning(code: ScanWarningCode, path: string, message: string): ScanWarning {
  return { code, path, message };
}

function toRepositoryPath(path: string): string {
  return sep === "/" ? path : path.split(sep).join("/");
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isPathInside(root: string, path: string): boolean {
  const candidate = relative(root, path);
  return candidate === "" || (!candidate.startsWith("..") && !isAbsolute(candidate));
}
