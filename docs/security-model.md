# Security Model

VibeGuard is local-first.

- It runs local `git diff`.
- It scans changed files and added lines from the diff.
- It does not upload source code.
- It does not upload dependency manifests.
- It does not auto-fix code.
- It masks detected secrets in output.

The tool is a pre-review safety layer, not a replacement for secure design review, tests, dependency auditing, or production security monitoring.

False negatives are expected in the first version because rules favor high-confidence findings over broad pattern matching.

