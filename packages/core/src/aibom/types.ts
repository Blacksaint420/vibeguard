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
  kind: AiAssetKind;
  name: string;
  file: string;
  line: number;
  confidence: "low" | "medium" | "high";
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
