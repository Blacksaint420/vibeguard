#!/usr/bin/env node
import { chmodSync, cpSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { stripTypeScriptTypes } from "node:module";

const root = fileURLToPath(new URL("..", import.meta.url));
const outDir = join(root, "dist");
const packageDirs = ["packages/cli/src", "packages/core/src", "packages/scanners/src", "packages/output/src"];

rmSync(outDir, { force: true, recursive: true });

for (const dir of packageDirs) {
  buildDirectory(join(root, dir), join(outDir, dir));
}

cpSync(join(root, "README.md"), join(outDir, "README.md"));
cpSync(join(root, "vibeguard.yml.example"), join(outDir, "vibeguard.yml.example"));
chmodSync(join(outDir, "packages/cli/src/index.js"), 0o755);

function buildDirectory(inputDir, outputDir) {
  for (const entry of readdirSync(inputDir, { withFileTypes: true })) {
    const inputPath = join(inputDir, entry.name);
    const outputPath = join(outputDir, entry.name.replace(/\.ts$/, ".js"));

    if (entry.isDirectory()) {
      buildDirectory(inputPath, outputPath);
      continue;
    }

    if (!entry.isFile() || !entry.name.endsWith(".ts")) continue;

    mkdirSync(dirname(outputPath), { recursive: true });
    const source = readFileSync(inputPath, "utf8");
    const transformed = stripTypeScriptTypes(source, { mode: "transform" })
      .replace(/from\s+["']([^"']+)\.ts["']/g, 'from "$1.js"')
      .replace(/import\(\s*["']([^"']+)\.ts["']\s*\)/g, 'import("$1.js")');
    writeFileSync(outputPath, transformed);
  }
}

console.log(`Built ${relative(root, outDir)}`);
