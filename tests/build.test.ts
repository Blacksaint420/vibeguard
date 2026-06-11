import test from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

test("build emits an installable JavaScript CLI", () => {
  const build = spawnSync("npm", ["run", "build"], { encoding: "utf8" });
  assert.equal(build.status, 0, build.stderr || build.stdout);
  assert.equal(existsSync("dist/packages/cli/src/index.js"), true);

  const doctor = spawnSync("node", ["dist/packages/cli/src/index.js", "doctor"], { encoding: "utf8" });
  assert.equal(doctor.status, 0, doctor.stderr || doctor.stdout);
  assert.equal(doctor.stdout.includes("No source upload"), true);
});

test("npm pack dry-run includes compiled CLI", () => {
  const npmCache = mkdtempSync(join(tmpdir(), "vibeguard-npm-cache-"));
  const packed = spawnSync("npm", ["pack", "--dry-run"], {
    encoding: "utf8",
    env: { ...process.env, NPM_CONFIG_CACHE: npmCache }
  });
  assert.equal(packed.status, 0, packed.stderr || packed.stdout);
  assert.equal(`${packed.stdout}\n${packed.stderr}`.includes("dist/packages/cli/src/index.js"), true);
});
