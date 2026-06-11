# Rules

The first VibeGuard rule set favors high-confidence changed-line findings.

## JavaScript and TypeScript

- `js-eval`
- `js-function-constructor`
- `js-sql-template-interpolation`
- `js-child-process-exec-user-input`
- `js-log-secret`
- `js-jwt-decode-no-verify`
- `js-permissive-cors`
- `js-insecure-cookie`
- `js-tls-disabled`
- `js-ssrf-request-input`
- `js-path-traversal`
- `js-weak-random-token`
- `js-express-route-no-obvious-auth`

## Python

- `py-eval-exec`
- `py-sql-string-format`
- `py-subprocess-shell-user-input`
- `py-pickle-loads`
- `py-yaml-unsafe-load`
- `py-requests-verify-false`
- `py-debug-true`
- `py-weak-random-token`
- `py-jwt-no-verify`
- `py-permissive-cors`

## Other Scanners

- Secrets: private keys, GitHub tokens, Slack tokens, cloud keys, generic credentials, authorization headers.
- Dependencies: broad ranges, unpinned versions, downgrades, suspicious names, lifecycle install scripts, optional vulnerability matches, lockfile-only changes.
- Docker: mutable or unpinned base images.
- GitHub Actions: mutable `uses:` refs, `write-all` permissions, `pull_request_target`.
- Sensitive files: `.env`, registry credentials, private keys, cloud credentials, kube config.
