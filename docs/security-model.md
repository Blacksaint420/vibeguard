# Security Model

VibeGuard is local-first.

- It scans the full repository by default.
- It runs local `git diff` only for explicit diff modes such as `--staged` and `--base`.
- It intentionally does not skip `.git`, dependency folders, generated folders, large files, or binary-looking files by default.
- It does not upload source code.
- It does not upload dependency manifests.
- It does not auto-fix code.
- It masks detected secrets in output.
- It handles unreadable files as scan warnings instead of crashing.
- It uses optional OSV vulnerability lookup only when explicitly requested.
- Optional vulnerability provider failures degrade to scan warnings by default; source, prompts, findings, AI BOM, graph data, and secrets are not uploaded.
- `vibeguard dashboard` reads local artifacts and writes local self-contained HTML. It does not use external scripts, stylesheets, fonts, images, analytics, telemetry, or upload flows.

The tool is a pre-review safety layer, not a replacement for secure design review, tests, dependency auditing, or production security monitoring.

False negatives are expected in the first version because rules favor high-confidence findings over broad pattern matching.
