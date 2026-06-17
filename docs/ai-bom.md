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
```

The AI BOM is evidence for security review, GRC inventory, and AI system ownership conversations. It is not a runtime discovery tool and does not execute project code.
