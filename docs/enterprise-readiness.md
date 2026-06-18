# Enterprise Readiness

VibeGuard is positioned as a local-first AI application security and agentic risk scanner.

## Enterprise Questions Answered

- What AI systems exist in this codebase?
- Which models, prompts, tools, MCP servers, and vector stores are present?
- Which agents can reach shell, filesystem, database, network, vector, or secret-bearing capabilities?
- Which risks map to OWASP LLM, NIST AI RMF, MITRE ATLAS, and Google SAIF?
- Which findings are blocked, suppressed, baselined, or accepted?
- What coverage was complete, partial, skipped, unreadable, or policy-excluded?

## Data Handling

The CLI scans local files in the developer machine or CI runner. It does not upload source code by default.

Optional OSV lookup sends package name, version, and ecosystem metadata only when `--vuln-provider osv` is selected.

## Recommended Enterprise Rollout

1. Run `vibeguard aibom` to build AI asset inventory.
2. Run `vibeguard graph` to review agent capabilities.
3. Run `vibeguard check --format risk-json` to produce control evidence.
4. Start with audit mode for one sprint.
5. Move to `examples/policies/vibeguard-agentic-strict.yml` for merge gating.
6. Enable `--strict-coverage` or `coverage.requireComplete: true` when teams are ready to fail incomplete scans.

## Release Gate

Before release, VibeGuard must pass:

```bash
npm test
npm run benchmark:aibom
npm run build
npm_config_cache=/private/tmp/vibeguard-npm-cache npm pack --dry-run
node dist/packages/cli/src/index.js check --quiet --format risk-json --output reports/vibeguard-risk.json
```

The repository self-scan must have zero blocking findings under `vibeguard.yml`.
