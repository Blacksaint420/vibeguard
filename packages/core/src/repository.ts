import { readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { relative, resolve, sep } from "node:path";

import type { DiffFile, ScanWarning } from "./types.ts";

export type RepositoryCollection = {
  files: DiffFile[];
  warnings: ScanWarning[];
  durationMs: number;
};

export function collectRepository(rootPath: string): RepositoryCollection {
  const started = Date.now();
  const warnings: ScanWarning[] = [];
  const root = resolve(rootPath);

  try {
    const stat = statSync(root);
    if (stat.isFile()) {
      const file = fileToDiffFile(root, root, warnings);
      return { files: file ? [file] : [], warnings, durationMs: Date.now() - started };
    }

    const files = walkDirectory(root, root, new Set([realpathSync(root)]), warnings)
      .sort((left, right) => left.path.localeCompare(right.path));
    return { files, warnings, durationMs: Date.now() - started };
  } catch (error) {
    warnings.push({ path: rootPath, message: errorMessage(error) });
    return { files: [], warnings, durationMs: Date.now() - started };
  }
}

export function collectRepositoryFiles(rootPath: string): DiffFile[] {
  return collectRepository(rootPath).files;
}

function walkDirectory(root: string, directory: string, ancestors: Set<string>, warnings: ScanWarning[]): DiffFile[] {
  const files: DiffFile[] = [];

  let entries;
  try {
    entries = readdirSync(directory, { withFileTypes: true });
  } catch (error) {
    warnings.push({ path: toRepositoryPath(relative(root, directory) || directory), message: errorMessage(error) });
    return files;
  }

  for (const entry of entries) {
    const fullPath = resolve(directory, entry.name);
    let stat;
    try {
      stat = statSync(fullPath);
    } catch (error) {
      warnings.push({ path: toRepositoryPath(relative(root, fullPath) || fullPath), message: errorMessage(error) });
      continue;
    }

    if (stat.isDirectory()) {
      const realPath = realpathSync(fullPath);
      if (ancestors.has(realPath)) continue;
      files.push(...walkDirectory(root, fullPath, new Set([...ancestors, realPath]), warnings));
      continue;
    }

    if (stat.isFile()) {
      const file = fileToDiffFile(root, fullPath, warnings);
      if (file) files.push(file);
    }
  }

  return files;
}

function fileToDiffFile(root: string, fullPath: string, warnings: ScanWarning[]): DiffFile | undefined {
  const path = toRepositoryPath(relative(root, fullPath) || fullPath);
  let content;
  try {
    content = readFileSync(fullPath).toString("utf8");
  } catch (error) {
    warnings.push({ path, message: errorMessage(error) });
    return undefined;
  }

  const lines = content.split(/\r?\n/);
  if (lines.at(-1) === "") lines.pop();

  return {
    path,
    oldPath: path,
    status: "modified",
    addedLines: lines.map((line, index) => ({ line: index + 1, content: line })),
    removedLines: []
  };
}

function toRepositoryPath(path: string): string {
  return sep === "/" ? path : path.split(sep).join("/");
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
