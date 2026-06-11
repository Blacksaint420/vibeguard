import { spawnSync } from "node:child_process";

import type { CheckOptions, DiffFile } from "./types.ts";

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

