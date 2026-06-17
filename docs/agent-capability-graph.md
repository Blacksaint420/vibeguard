# Agent Capability Graph

The Agent Capability Graph models how AI assets connect to sensitive capabilities.

Graph nodes include:

- Agents.
- Tools.
- Models.
- Prompts.
- Vector stores.
- MCP servers.
- Capabilities such as shell, filesystem, network, database, secret access, and vector search.

Run:

```bash
vibeguard graph --format graph-json --output vibeguard-agent-graph.json
vibeguard graph --format graph-markdown --output vibeguard-agent-graph.md
```

High-risk paths show agent reachability to capabilities that need approval, least privilege, tenant isolation, runtime containment, or human review.
