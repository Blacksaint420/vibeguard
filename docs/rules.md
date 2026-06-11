# Rules

The default VibeGuard report favors exploitable, high-confidence findings and maps them to OWASP Top 10 for LLM Applications 2025 where applicable. Lower-confidence audit signals still exist in the scanners, but normal `vibeguard check` output hides them through `minConfidence: high`.

Default code and secret/PII findings are limited to first-party source paths. Vendored and generated paths such as `node_modules`, `.worktrees`, `dist`, `build`, `coverage`, `.next`, and `.git` are still collected by full scans, but their code examples are not treated as exploitable first-party findings. Dependency vulnerability inventory is built from first-party manifests and lockfiles.

## OWASP LLM 2025 Coverage

- `LLM01:2025 Prompt Injection`: user-controlled content enters system or developer prompts.
- `LLM02:2025 Sensitive Information Disclosure`: concrete tokens, credentials, private keys, high-confidence PII, and public data rules.
- `LLM03:2025 Supply Chain`: dependency/component versions confirmed vulnerable by a vulnerability provider.
- `LLM04:2025 Data and Model Poisoning`: untrusted request content is written directly into vector or embedding stores.
- `LLM05:2025 Improper Output Handling`: LLM output reaches code execution sinks.
- `LLM06:2025 Excessive Agency`: automatic tool calls are connected to command, file-write, or destructive sinks.
- `LLM07:2025 System Prompt Leakage`: system or developer prompt text is returned to callers.
- `LLM08:2025 Vector and Embedding Weaknesses`: request-controlled metadata filters are passed into vector search.
- `LLM10:2025 Unbounded Consumption`: request-controlled token budgets are passed into model calls.

## JavaScript and TypeScript

- `llm01-direct-prompt-injection`
- `llm04-untrusted-vector-ingestion`
- `llm05-output-exec`
- `llm06-auto-tool-dangerous-sink`
- `llm07-system-prompt-leak`
- `llm08-user-controlled-vector-filter`
- `llm10-user-controlled-token-budget`
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

- Secrets and PII: private keys, GitHub tokens, Slack tokens, cloud keys, authorization headers, US SSNs, and credit card numbers with checksum validation.
- Dependencies: default LLM03 findings require vulnerable package matches from `--vuln-provider mock|osv`. Lifecycle install scripts, lockfile install-script metadata, insecure lockfile URLs, downgrades, suspicious names, broad ranges, and lockfile-only changes require `--min-confidence medium`.
- Docker: mutable or unpinned base images require `--min-confidence medium`.
- GitHub Actions: mutable `uses:` refs, `write-all` permissions, and `pull_request_target` require `--min-confidence medium`.
- Sensitive file path changes require `--min-confidence medium`; concrete secrets inside those files are still default findings.
