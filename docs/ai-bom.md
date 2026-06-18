# AI Bill of Materials

The AI BOM identifies AI-specific assets in a repository without uploading source code.

It inventories:

- AI providers.
- Models.
- Prompts.
- Agents.
- Tools.
- MCP servers.
- Vector stores.
- Data stores.

Run:

```bash
vibeguard aibom --format aibom-json --output vibeguard-aibom.json
vibeguard aibom --format aibom-markdown --output vibeguard-aibom.md
vibeguard aibom approve --output .vibeguard/approved-aibom.json
vibeguard aibom diff --approved-aibom .vibeguard/approved-aibom.json --format markdown
```

The AI BOM is evidence for security review, GRC inventory, and AI system ownership conversations. It is not a runtime discovery tool and does not execute project code.

## Evidence Strength

Each asset includes evidence metadata so reviewers can tell how dependable the inventory claim is:

- `direct`: detected from explicit syntax such as a provider constructor, model literal, tool definition, vector-store call, or MCP config entry.
- `same-file`: inferred from a local reference in the same file, such as a tool name listed in an agent `tools` array.
- `same-module`: inferred from related AI assets found in the same source module.
- `repository-inferred`: inferred from repository-level fallback linking; useful for review, but not proof of runtime reachability.
- `unknown`: retained for compatibility when a source cannot be classified.

Every asset also includes a deterministic `fingerprint` built from policy-relevant fields. The fingerprint excludes generated timestamps, absolute target paths, and evidence snippets, so it can be used for approved-BOM drift review.

Use `aibom-json` when you need the full `fingerprint`, `evidenceStrength`, `evidenceSource`, `detectionMethod`, and `relatedLocations` fields for audit evidence.

See [`docs/ai-bom-governance.md`](./ai-bom-governance.md) for approved BOM workflows and governance policy gates.
