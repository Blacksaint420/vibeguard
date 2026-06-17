import type {
  AgentCapabilityGraph,
  AgentGraphEdge,
  AgentGraphNode,
  AgentGraphRisk,
  AiAsset,
  AiBom,
  AiCapability
} from "./types.ts";

const HIGH_RISK_CAPABILITIES: AiCapability[] = ["shell", "filesystem", "database", "secret-access", "mcp-tool"];

export function buildAgentCapabilityGraph(bom: AiBom): AgentCapabilityGraph {
  const nodes = buildNodes(bom);
  const edges = buildEdges(bom);
  const risks = buildGraphRisks(bom);

  return {
    tool: "vibeguard",
    schemaVersion: "vibeguard.agentGraph.v1",
    generatedAt: bom.generatedAt,
    targetPath: bom.targetPath,
    summary: {
      agents: bom.agents.length,
      tools: bom.tools.length,
      capabilities: new Set(edges.map((edge) => edge.capability).filter(Boolean)).size,
      highRiskPaths: risks.length
    },
    nodes,
    edges,
    risks
  };
}

function buildNodes(bom: AiBom): AgentGraphNode[] {
  const assets = allAssets(bom);
  const assetNodes = assets.map((asset) => ({
    id: asset.id,
    kind: asset.kind,
    label: asset.name,
    file: asset.file,
    line: asset.line
  }));

  const capabilityNodes = [...new Set(assets.flatMap((asset) => asset.capabilities))].map((capability) => ({
    id: `capability:${capability}`,
    kind: "capability" as const,
    label: capability
  }));

  return [...assetNodes, ...capabilityNodes];
}

function buildEdges(bom: AiBom): AgentGraphEdge[] {
  const edges: AgentGraphEdge[] = [];

  for (const agent of bom.agents) {
    for (const model of bom.models) {
      edges.push({ from: agent.id, to: model.id, relation: "calls", capability: "llm-call" });
    }

    for (const prompt of bom.prompts) {
      edges.push({ from: agent.id, to: prompt.id, relation: "uses", capability: "prompt-control" });
    }

    for (const tool of bom.tools) {
      edges.push({ from: agent.id, to: tool.id, relation: "uses", capability: primaryCapability(tool) });
    }
  }

  for (const tool of bom.tools) {
    for (const capability of tool.capabilities) {
      edges.push({ from: tool.id, to: `capability:${capability}`, relation: "exposes", capability });
    }
  }

  for (const server of bom.mcpServers) {
    for (const capability of server.capabilities) {
      edges.push({ from: server.id, to: `capability:${capability}`, relation: "exposes", capability });
    }
  }

  for (const vectorStore of bom.vectorStores) {
    edges.push({ from: vectorStore.id, to: "capability:vector-search", relation: "retrieves", capability: "vector-search" });
  }

  return dedupeEdges(edges);
}

function buildGraphRisks(bom: AiBom): AgentGraphRisk[] {
  const risks: AgentGraphRisk[] = [];
  const agents = bom.agents.length ? bom.agents : [undefined];
  const highRiskAssets = [...bom.tools, ...bom.mcpServers].filter((asset) =>
    asset.capabilities.some((capability) => HIGH_RISK_CAPABILITIES.includes(capability))
  );

  for (const asset of highRiskAssets) {
    for (const capability of asset.capabilities.filter((item) => HIGH_RISK_CAPABILITIES.includes(item))) {
      const agent = agents[0];
      risks.push({
        ruleId: graphRuleForCapability(capability),
        title: graphTitleForCapability(capability),
        severity: capability === "shell" || capability === "secret-access" ? "critical" : "high",
        agentId: agent?.id,
        assetId: asset.id,
        capability,
        path: agent ? [agent.id, asset.id, `capability:${capability}`] : [asset.id, `capability:${capability}`],
        evidence: `${asset.name} exposes ${capability} capability${agent ? ` reachable from ${agent.name}` : ""}.`,
        suggestedFix: graphFixForCapability(capability)
      });
    }
  }

  return risks;
}

function graphRuleForCapability(capability: AiCapability): string {
  if (capability === "shell") return "agent-capability-shell-without-approval";
  if (capability === "filesystem") return "agent-capability-filesystem-access";
  if (capability === "database") return "agent-capability-database-access";
  if (capability === "secret-access") return "agent-capability-secret-access";
  if (capability === "mcp-tool") return "agent-capability-mcp-tool-access";
  return "agent-capability-high-risk";
}

function graphTitleForCapability(capability: AiCapability): string {
  if (capability === "shell") return "Agent can reach shell execution";
  if (capability === "filesystem") return "Agent can reach filesystem access";
  if (capability === "database") return "Agent can reach database access";
  if (capability === "secret-access") return "Agent can reach secret-bearing configuration";
  if (capability === "mcp-tool") return "Agent can reach MCP tool capability";
  return "Agent can reach high-risk capability";
}

function graphFixForCapability(capability: AiCapability): string {
  if (capability === "shell") return "Require explicit human approval, structured arguments, and command allowlists before shell execution.";
  if (capability === "filesystem") return "Constrain filesystem access to explicit roots and read/write permissions.";
  if (capability === "database") return "Require server-side authorization, scoped credentials, and query allowlists.";
  if (capability === "secret-access") return "Remove direct secret exposure from agent tools and use brokered, scoped credentials.";
  if (capability === "mcp-tool") return "Review MCP server capabilities and require per-tool approval for dangerous actions.";
  return "Add least-privilege controls before exposing this capability to an agent.";
}

function primaryCapability(asset: AiAsset): AiCapability | undefined {
  return asset.capabilities.find((capability) => HIGH_RISK_CAPABILITIES.includes(capability)) ?? asset.capabilities[0];
}

function allAssets(bom: AiBom): AiAsset[] {
  return [
    ...bom.providers,
    ...bom.models,
    ...bom.prompts,
    ...bom.agents,
    ...bom.tools,
    ...bom.vectorStores,
    ...bom.mcpServers,
    ...bom.dataStores
  ];
}

function dedupeEdges(edges: AgentGraphEdge[]): AgentGraphEdge[] {
  return [...new Map(edges.map((edge) => [`${edge.from}\0${edge.to}\0${edge.relation}\0${edge.capability ?? ""}`, edge])).values()];
}
