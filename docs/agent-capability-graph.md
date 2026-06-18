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

## Evidence Strength

Graph edges and high-risk paths include evidence metadata:

- `direct`: the asset directly exposes the capability.
- `same-file`: the agent and tool relationship is supported by a same-file reference, such as `tools: [shellTool]`.
- `same-module`: the relationship is inferred from assets detected in the same source file or module.
- `repository-inferred`: VibeGuard kept the conservative repository-level fallback edge, but the path should be treated as review evidence rather than proven runtime reachability.
- `unknown`: retained for compatibility when evidence cannot be classified.

The graph keeps existing broad reachability behavior for safety, but Markdown, console, and JSON outputs label inferred paths so companies can separate proven exposure from assumptions during security review.
