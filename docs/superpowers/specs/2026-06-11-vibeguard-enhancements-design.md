# VibeGuard Enhancement Design

## Goal

Implement the seven requested enhancement areas: npm distribution, scan ergonomics, resilient repository scanning, noise controls, rule quality, dependency intelligence, and richer reports.

## Scope

- Build compiled JavaScript into `dist/` and point the npm `bin` entry at the compiled CLI.
- Add `--quiet`, `--no-color`, `--max-findings`, `--min-confidence`, `--vuln-provider`, and `--format html`.
- Preserve exhaustive full-repository scans while recording warnings for unreadable or broken paths.
- Add scan metadata: scan mode, target path, files scanned, duration, warning count, and truncation status.
- Reduce obvious code-rule false positives from string/comment matches.
- Add dependency lifecycle script detection and optional OSV/mock vulnerability providers.
- Improve Markdown, SARIF, JSON, table, and HTML reports.

## Constraints

- No runtime source upload.
- OSV lookup is opt-in and sends package names/versions only.
- No default path skips.
- Keep implementation dependency-free for now.
