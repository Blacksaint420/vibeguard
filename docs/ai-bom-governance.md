# AI BOM Governance

AI BOM governance compares the current local AI inventory against an approved AI BOM and optional policy rules. It is audit-only by default and does not upload source, prompts, findings, AI BOMs, graphs, or secrets.

Create an approved BOM from the current repository:

```bash
vibeguard aibom approve --output .vibeguard/approved-aibom.json
```

Review drift against the approved BOM:

```bash
vibeguard aibom diff --approved-aibom .vibeguard/approved-aibom.json --format markdown
```

Run a normal security scan with governance evidence:

```bash
vibeguard check --approved-aibom .vibeguard/approved-aibom.json --ai-governance-mode audit
```

Use blocking only when the team intentionally opts in:

```bash
vibeguard check --approved-aibom .vibeguard/approved-aibom.json --ai-governance-mode block
```

Governance detects unauthorized providers, models, and MCP servers, blocked capabilities, and high-risk capability drift such as newly introduced shell or secret-access capability. Violations appear in JSON, Markdown, HTML, SARIF, and risk-json output.

Policy examples:

- `examples/policies/vibeguard-ai-governance.yml` starts in audit mode.
- `examples/policies/vibeguard-ai-governance-strict.yml` enables blocking governance controls.
- `examples/approved-aibom/vibeguard-approved-aibom.json` is an empty approved-BOM starter.
