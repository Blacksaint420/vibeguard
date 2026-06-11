import { readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { relative, resolve, sep } from "node:path";

import type { DiffFile } from "./types.ts";

export function collectRepositoryFiles(rootPath: string): DiffFile[] {
  const root = resolve(rootPath);
  const stat = statSync(root);

  if (stat.isFile()) {
    return [fileToDiffFile(root, root)];
  }

  return walkDirectory(root, root, new Set([realpathSync(root)])).sort((left, right) => left.path.localeCompare(right.path));
}

function walkDirectory(root: string, directory: string, ancestors: Set<string>): DiffFile[] {
  const files: DiffFile[] = [];

  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const fullPath = resolve(directory, entry.name);
    const stat = statSync(fullPath);

    if (stat.isDirectory()) {
      const realPath = realpathSync(fullPath);
      if (ancestors.has(realPath)) continue;
      files.push(...walkDirectory(root, fullPath, new Set([...ancestors, realPath])));
      continue;
    }

    if (stat.isFile()) {
      files.push(fileToDiffFile(root, fullPath));
    }
  }

  return files;
}

function fileToDiffFile(root: string, fullPath: string): DiffFile {
  const content = readFileSync(fullPath).toString("utf8");
  const lines = content.split(/\r?\n/);
  if (lines.at(-1) === "") lines.pop();
  const path = toRepositoryPath(relative(root, fullPath) || fullPath);

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
