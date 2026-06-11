# Rules

The default VibeGuard report favors high-confidence findings and maps them to OWASP Top 10 for LLM Applications 2025 where applicable. Lower-confidence audit signals still exist in the scanners, but normal `vibeguard check` output hides them through `minConfidence: high`.

## OWASP LLM 2025 Coverage

- `LLM01:2025 Prompt Injection`: user-controlled content enters system or developer prompts.
- `LLM02:2025 Sensitive Information Disclosure`: secrets, sensitive files, and public data rules.
- `LLM03:2025 Supply Chain`: install scripts, vulnerable packages, dependency downgrades, suspicious package names, insecure lockfile URLs, mutable Docker images, and mutable CI components.
- `LLM05:2025 Improper Output Handling`: LLM output reaches code execution sinks, or string execution sinks are present in code.
- `LLM07:2025 System Prompt Leakage`: system or developer prompt text is returned to callers.

## JavaScript and TypeScript

- `llm01-direct-prompt-injection`
- `llm05-output-exec`
- `llm07-system-prompt-leak`
- `js-eval`
- `js-function-constructor`
- `js-sql-template-interpolation`
- `js-prisma-raw-unsafe`
- `js-child-process-exec-user-input`
- `js-log-secret`
- `js-jwt-decode-no-verify`
- `js-permissive-cors`
- `js-insecure-cookie`
- `js-tls-disabled`
- `js-ssrf-request-input`
- `js-nextjs-ssrf-query-fetch`
- `js-path-traversal`
- `js-weak-random-token`
- `js-supabase-service-role-client`
- `js-express-route-no-obvious-auth` (`--min-confidence low`)

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
- `py-django-csrf-exempt`
- `py-flask-route-no-obvious-auth` (`--min-confidence low`)

## Firebase Rules

- `firebase-public-rules`

## Other Scanners

- Secrets: private keys, GitHub tokens, Slack tokens, cloud keys, generic credentials, authorization headers.
- Dependencies: lifecycle install scripts, lockfile install-script metadata, insecure lockfile resolved URLs, vulnerable package matches, downgrades, and suspicious package names. Broad ranges and lockfile-only changes require `--min-confidence medium`.
- Docker: mutable or unpinned base images.
- GitHub Actions: mutable `uses:` refs, `write-all` permissions, `pull_request_target`.
- Sensitive files: `.env`, registry credentials, private keys, cloud credentials, kube config.
