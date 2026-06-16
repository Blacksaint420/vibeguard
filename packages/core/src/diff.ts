import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";

import type { ChangedLine, CheckOptions, DiffFile } from "./types.ts";

export function collectGitDiff(options: CheckOptions = {}): string {
  const cwd = options.cwd ?? process.cwd();
  const args = ["diff", "--unified=0"];

  if (options.staged) {
    args.push("--staged");
  } else if (options.base) {
    args.push(`${options.base}...HEAD`);
  }

  const result = spawnSync("git", args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024
  });

  if (result.status !== 0) {
    throw new Error((result.stderr || "git diff failed").trim());
  }

  return result.stdout ?? "";
}

export function parseUnifiedDiff(diffText: string): DiffFile[] {
  const files: DiffFile[] = [];
  let current: DiffFile | undefined;
  let oldLine = 0;
  let newLine = 0;

  for (const rawLine of diffText.split(/\r?\n/)) {
    if (rawLine.startsWith("diff --git ")) {
      const match = /^diff --git a\/(.+) b\/(.+)$/.exec(rawLine);
      current = {
        oldPath: match?.[1] ?? "",
        path: match?.[2] ?? "",
        status: "modified",
        addedLines: [],
        removedLines: []
      };
      files.push(current);
      continue;
    }

    if (!current) continue;

    if (rawLine.startsWith("new file mode ")) {
      current.status = "added";
      continue;
    }

    if (rawLine.startsWith("deleted file mode ")) {
      current.status = "deleted";
      continue;
    }

    if (rawLine.startsWith("rename from ")) {
      current.status = "renamed";
      current.oldPath = rawLine.slice("rename from ".length);
      continue;
    }

    if (rawLine.startsWith("rename to ")) {
      current.status = "renamed";
      current.path = rawLine.slice("rename to ".length);
      continue;
    }

    if (rawLine.startsWith("--- ")) {
      const oldPath = rawLine.slice(4);
      if (oldPath.startsWith("a/")) current.oldPath = oldPath.slice(2);
      continue;
    }

    if (rawLine.startsWith("+++ ")) {
      const nextPath = rawLine.slice(4);
      if (nextPath === "/dev/null") {
        current.path = current.oldPath;
        current.status = "deleted";
      } else if (nextPath.startsWith("b/")) {
        current.path = nextPath.slice(2);
      }
      continue;
    }

    if (rawLine.startsWith("@@ ")) {
      const hunk = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(rawLine);
      if (hunk) {
        oldLine = Number(hunk[1]);
        newLine = Number(hunk[2]);
      }
      continue;
    }

    if (rawLine.startsWith("+")) {
      current.addedLines.push({ line: newLine, content: rawLine.slice(1) });
      newLine += 1;
      continue;
    }

    if (rawLine.startsWith("-")) {
      current.removedLines.push({ line: oldLine, content: rawLine.slice(1) });
      oldLine += 1;
      continue;
    }

    if (rawLine.startsWith(" ")) {
      oldLine += 1;
      newLine += 1;
    }
  }

  return files.filter((file) => file.path.length > 0);
}

export function getChangedLineSet(file: DiffFile): Set<number> {
  return new Set(file.addedLines.map((line) => line.line));
}

export function enrichDiffFilesWithFullContext(
  files: DiffFile[],
  options: { cwd?: string; staged?: boolean } = {}
): DiffFile[] {
  const cwd = resolve(options.cwd ?? process.cwd());

  return files.map((file) => {
    if (file.status === "deleted" || file.allLines) return file;

    const content = options.staged
      ? readStagedFileContent(cwd, file.path) ?? readWorkingTreeFileContent(cwd, file.path)
      : readWorkingTreeFileContent(cwd, file.path);

    if (content === undefined) return file;
    return {
      ...file,
      allLines: textToChangedLines(content)
    };
  });
}

function readStagedFileContent(cwd: string, path: string): string | undefined {
  const result = spawnSync("git", ["show", `:${path}`], {
    cwd,
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024
  });

  if (result.status === 0) return result.stdout ?? "";

  // If the index copy is unavailable, use the working tree so scanners can still
  // reason over surrounding syntax for staged diffs instead of falling back to added lines only.
  return undefined;
}

function readWorkingTreeFileContent(cwd: string, path: string): string | undefined {
  const fullPath = resolve(cwd, path);
  if (!isPathInside(cwd, fullPath)) return undefined;

  try {
    return readFileSync(fullPath, "utf8");
  } catch {
    return undefined;
  }
}

function textToChangedLines(content: string): ChangedLine[] {
  const lines = content.split(/\r?\n/);
  if (lines.at(-1) === "") lines.pop();
  return lines.map((line, index) => ({ line: index + 1, content: line }));
}

function isPathInside(root: string, path: string): boolean {
  const candidate = relative(root, path);
  return candidate === "" || (!candidate.startsWith("..") && !isAbsolute(candidate));
}
