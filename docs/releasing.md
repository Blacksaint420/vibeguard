# Releasing

This project publishes the `vibeguard` npm package and the GitHub Action from the same repository.

## Prerequisites

- The npm package name is available to the maintainer account.
- The repository has an `NPM_TOKEN` secret with publish access.
- GitHub Actions has `id-token: write` permission for npm provenance.
- Security contact details in `SECURITY.md` are valid.

## Release Checklist

1. Update `CHANGELOG.md` and remove the `Unreleased` marker for the version being published.
2. Confirm `package.json` has the intended version, repository URL, license, files list, and public publish config.
3. Run the local verification suite:

```bash
npm test
npm run build
npm pack --dry-run
npm run vibeguard:dist -- check --quiet --format json
```

4. Confirm `npm pack --dry-run` includes compiled `dist/` files and excludes local reports, baselines, package tarballs, and development-only artifacts.
5. Commit the release changes and create a GitHub release for the matching tag, for example `v0.1.0`.
6. After the release workflow publishes to npm, smoke test the package:

```bash
npx --yes vibeguard@latest doctor
npx --yes vibeguard@latest check --quiet
```

## Notes

- Publishing is triggered by the GitHub `release.published` event.
- Generated self-scan reports are local artifacts and should not be committed.
- Optional OSV dependency lookup must remain opt-in and documented.
