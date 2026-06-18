import type {
  AgentCapabilityGraph,
  AgentGraphEdge,
  AgentGraphNode,
  AgentGraphRisk,
  AiAsset,
  AiBom,
  AiCapability
} from "./types.ts";
import type { EvidenceStrength } from "../types.ts";

const HIGH_RISK_CAPABILITIES: AiCapability[] = ["shell", "filesystem", "database", "secret-access", "mcp-tool"];

export function buildAgentCapabilityGraph(bom: AiBom): AgentCapabilityGraph {
  const nodes = buildNodes(bom);
  const edges = buildEdges(bom);
  const risks = buildGraphRisks(bom, edges);

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
      edges.push(assetEdge(agent, model, "calls", "llm-call", linkedAssetEvidence(agent, model, "model")));
    }

    for (const prompt of bom.prompts) {
      edges.push(assetEdge(agent, prompt, "uses", "prompt-control", linkedAssetEvidence(agent, prompt, "prompt")));
    }

    for (const tool of bom.tools) {
      edges.push(assetEdge(agent, tool, "uses", primaryCapability(tool), linkedAssetEvidence(agent, tool, "tool")));
    }
  }

  for (const tool of bom.tools) {
    for (const capability of tool.capabilities) {
      edges.push(capabilityEdge(tool, capability, "exposes"));
    }
  }

  for (const server of bom.mcpServers) {
    for (const capability of server.capabilities) {
      edges.push(capabilityEdge(server, capability, "exposes"));
    }
  }

  for (const vectorStore of bom.vectorStores) {
    edges.push(capabilityEdge(vectorStore, "vector-search", "retrieves"));
  }

  return dedupeEdges(edges);
}

function buildGraphRisks(bom: AiBom, edges: AgentGraphEdge[]): AgentGraphRisk[] {
  const risks: AgentGraphRisk[] = [];
  const agents = bom.agents.length ? bom.agents : [undefined];
  const highRiskAssets = [...bom.tools, ...bom.mcpServers].filter((asset) =>
    asset.capabilities.some((capability) => HIGH_RISK_CAPABILITIES.includes(capability))
  );

  for (const asset of highRiskAssets) {
    for (const capability of asset.capabilities.filter((item) => HIGH_RISK_CAPABILITIES.includes(item))) {
      const agent = agents[0];
      const riskEvidence = riskEvidenceForPath(agent, asset, capability, edges);
      risks.push({
        ruleId: graphRuleForCapability(capability),
        title: graphTitleForCapability(capability),
        severity: capability === "shell" || capability === "secret-access" ? "critical" : "high",
        agentId: agent?.id,
        assetId: asset.id,
        capability,
        path: agent ? [agent.id, asset.id, `capability:${capability}`] : [asset.id, `capability:${capability}`],
        evidenceStrength: riskEvidence.evidenceStrength,
        evidenceSource: riskEvidence.evidenceSource,
        detectionMethod: riskEvidence.detectionMethod,
        relatedLocations: riskEvidence.relatedLocations,
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

function assetEdge(
  from: AiAsset,
  to: AiAsset,
  relation: AgentGraphEdge["relation"],
  capability: AiCapability | undefined,
  evidence: { evidenceStrength: EvidenceStrength; evidenceSource: string; detectionMethod: string }
): AgentGraphEdge {
  return {
    from: from.id,
    to: to.id,
    relation,
    capability,
    evidenceStrength: evidence.evidenceStrength,
    evidenceSource: evidence.evidenceSource,
    detectionMethod: evidence.detectionMethod,
    relatedLocations: [
      { file: from.file, line: from.line, label: from.kind },
      { file: to.file, line: to.line, label: to.kind }
    ]
  };
}

function capabilityEdge(asset: AiAsset, capability: AiCapability, relation: AgentGraphEdge["relation"]): AgentGraphEdge {
  return {
    from: asset.id,
    to: `capability:${capability}`,
    relation,
    capability,
    evidenceStrength: asset.evidenceStrength,
    evidenceSource: asset.evidenceSource,
    detectionMethod: `${asset.detectionMethod}:capability`,
    relatedLocations: [{ file: asset.file, line: asset.line, label: asset.kind }]
  };
}

function linkedAssetEvidence(
  agent: AiAsset,
  asset: AiAsset,
  kind: "model" | "prompt" | "tool"
): { evidenceStrength: EvidenceStrength; evidenceSource: string; detectionMethod: string } {
  if (kind === "tool" && agent.file === asset.file && agentReferencesTool(agent, asset.name)) {
    return {
      evidenceStrength: "same-file",
      evidenceSource: "agent tools array references tool in same file",
      detectionMethod: "agent-tool-reference"
    };
  }

  if (agent.file === asset.file) {
    return {
      evidenceStrength: "same-module",
      evidenceSource: `agent and ${kind} detected in same source file`,
      detectionMethod: `same-module-${kind}-link`
    };
  }

  return {
    evidenceStrength: "repository-inferred",
    evidenceSource: `repository-level fallback linked agent to ${kind}`,
    detectionMethod: "repository-fallback-link"
  };
}

function agentReferencesTool(agent: AiAsset, toolName: string): boolean {
  const tools = typeof agent.metadata.tools === "string" ? agent.metadata.tools.split(",").map((tool) => tool.trim()) : [];
  return tools.includes(toolName);
}

function riskEvidenceForPath(
  agent: AiAsset | undefined,
  asset: AiAsset,
  capability: AiCapability,
  edges: AgentGraphEdge[]
): Pick<AgentGraphRisk, "evidenceStrength" | "evidenceSource" | "detectionMethod" | "relatedLocations"> {
  const capabilityEdge = edges.find((edge) => edge.from === asset.id && edge.to === `capability:${capability}`);
  const agentEdge = agent ? edges.find((edge) => edge.from === agent.id && edge.to === asset.id) : undefined;
  const pathEdges = [agentEdge, capabilityEdge].filter(Boolean) as AgentGraphEdge[];
  const evidenceStrength = weakestEvidence(pathEdges.map((edge) => edge.evidenceStrength));
  const limitingEdge = pathEdges.find((edge) => edge.evidenceStrength === evidenceStrength) ?? capabilityEdge ?? agentEdge;

  return {
    evidenceStrength,
    evidenceSource: limitingEdge?.evidenceSource ?? asset.evidenceSource,
    detectionMethod: limitingEdge?.detectionMethod ?? asset.detectionMethod,
    relatedLocations: uniqueRelatedLocations(pathEdges.flatMap((edge) => edge.relatedLocations ?? []))
  };
}

function weakestEvidence(values: EvidenceStrength[]): EvidenceStrength {
  if (values.length === 0) return "unknown";
  return values.reduce((weakest, value) => evidenceRank[value] < evidenceRank[weakest] ? value : weakest);
}

const evidenceRank: Record<EvidenceStrength, number> = {
  unknown: 0,
  "repository-inferred": 1,
  "same-module": 2,
  "same-file": 3,
  direct: 4
};

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
  const byKey = new Map<string, AgentGraphEdge>();
  for (const edge of edges) {
    const key = `${edge.from}\0${edge.to}\0${edge.relation}\0${edge.capability ?? ""}`;
    const existing = byKey.get(key);
    if (!existing || evidenceRank[edge.evidenceStrength] > evidenceRank[existing.evidenceStrength]) {
      byKey.set(key, edge);
    }
  }
  return [...byKey.values()];
}

function uniqueRelatedLocations(locations: NonNullable<AgentGraphRisk["relatedLocations"]>): NonNullable<AgentGraphRisk["relatedLocations"]> {
  return [...new Map(locations.map((location) => [`${location.file}\0${location.line}\0${location.label ?? ""}`, location])).values()];
}
