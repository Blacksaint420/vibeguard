# Full Repository Scan Design

## Goal

Make VibeGuard plug and play by changing `vibeguard check` to scan an entire repository with minimal user interaction.

## Approved Behavior

- `vibeguard check` scans the full current repository.
- `vibeguard check <path>` scans the full repository or directory at that path.
- `vibeguard check --staged` keeps staged git-diff scanning.
- `vibeguard check --base <branch>` keeps branch git-diff scanning.
- All output formats continue to work for full scans and diff scans.

## No Default Path Skips

The full scan does not skip `.git`, `node_modules`, `dist`, `build`, `coverage`, `.next`, virtualenv folders, large files, or binary-looking files by default. Users can still opt into project-specific excludes through `vibeguard.yml`.

## Implementation Shape

Add a repository collector in `packages/core` that walks the target path and converts every file into the same `DiffFile` shape already consumed by scanners. This preserves the scanner, policy, finding, and formatter contracts while expanding the source of scanned files beyond git diffs.

## Tradeoff

This behavior is intentionally exhaustive and may be slower or noisier on large repositories. That is acceptable for the requested plug-and-play model because it avoids hidden omissions.
