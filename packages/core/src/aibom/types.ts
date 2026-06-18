import type { EvidenceStrength } from "../types.ts";

export type AiAssetKind =
  | "provider"
  | "model"
  | "prompt"
  | "agent"
  | "tool"
  | "vector-store"
  | "mcp-server"
  | "data-store";

export type AiCapability =
  | "llm-call"
  | "prompt-control"
  | "shell"
  | "filesystem"
  | "network"
  | "database"
  | "vector-search"
  | "secret-access"
  | "mcp-tool"
  | "external-provider";

export type AiAsset = {
  id: string;
  fingerprint: string;
  kind: AiAssetKind;
  name: string;
  file: string;
  line: number;
  confidence: "low" | "medium" | "high";
  evidenceStrength: EvidenceStrength;
  evidenceSource: string;
  detectionMethod: string;
  relatedLocations?: Array<{ file: string; line: number; label?: string }>;
  capabilities: AiCapability[];
  metadata: Record<string, string | number | boolean>;
};

export type AiBomSummary = {
  providers: number;
  models: number;
  prompts: number;
  agents: number;
  tools: number;
  vectorStores: number;
  mcpServers: number;
  dataStores: number;
  highRiskCapabilities: AiCapability[];
};

export type AiBom = {
  tool: "vibeguard";
  schemaVersion: "vibeguard.aibom.v1";
  generatedAt: string;
  targetPath: string;
  summary: AiBomSummary;
  providers: AiAsset[];
  models: AiAsset[];
  prompts: AiAsset[];
  agents: AiAsset[];
  tools: AiAsset[];
  vectorStores: AiAsset[];
  mcpServers: AiAsset[];
  dataStores: AiAsset[];
};

export type AiBomOptions = {
  targetPath: string;
  generatedAt?: string;
};

export type AgentGraphNodeKind = AiAssetKind | "capability";

export type AgentGraphNode = {
  id: string;
  kind: AgentGraphNodeKind;
  label: string;
  file?: string;
  line?: number;
};

export type AgentGraphEdge = {
  from: string;
  to: string;
  relation: "uses" | "calls" | "exposes" | "retrieves" | "connects";
  capability?: AiCapability;
  evidenceStrength: EvidenceStrength;
  evidenceSource: string;
  detectionMethod: string;
  relatedLocations?: Array<{ file: string; line: number; label?: string }>;
};

export type AgentGraphRisk = {
  ruleId: string;
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  agentId?: string;
  assetId: string;
  capability: AiCapability;
  path: string[];
  evidenceStrength: EvidenceStrength;
  evidenceSource: string;
  detectionMethod: string;
  relatedLocations?: Array<{ file: string; line: number; label?: string }>;
  evidence: string;
  suggestedFix: string;
};

export type AgentCapabilityGraph = {
  tool: "vibeguard";
  schemaVersion: "vibeguard.agentGraph.v1";
  generatedAt: string;
  targetPath: string;
  summary: {
    agents: number;
    tools: number;
    capabilities: number;
    highRiskPaths: number;
  };
  nodes: AgentGraphNode[];
  edges: AgentGraphEdge[];
  risks: AgentGraphRisk[];
};
