# Local Release And Production Git Deployment

VibeGuard is currently distributed as a local-install application from the GitHub repository. It is not registered with npm yet, and release automation must not publish to the npm registry.

## Prerequisites

- The local checkout is on the branch intended for production git.
- GitHub Actions for CI and main change readiness are passing.
- Security contact details in `SECURITY.md` are valid.

## Production Git Checklist

1. Update `CHANGELOG.md` when the change is user-visible.
2. Confirm `package.json` is marked private so accidental npm publication is blocked.
3. Run the local verification suite:

```bash
npm test
npm run build
npm pack --dry-run
npm run vibeguard:dist -- check --quiet --format json
```

4. Confirm `npm pack --dry-run` can produce a local artifact for inspection and excludes local reports, baselines, package tarballs, and development-only artifacts.
5. Commit the verified changes and push `main` to `origin`.
6. Smoke test the local install path from a fresh checkout when needed:

```bash
npm install
npm run build
npm link
vibeguard doctor
vibeguard check --quiet
```

## Notes

- GitHub release automation verifies the local package artifact only; it does not publish to npm.
- Generated self-scan reports are local artifacts and should not be committed.
- Optional OSV dependency lookup must remain opt-in and documented.
