import { createHash } from "node:crypto";

import type { DiffFile, EvidenceStrength } from "../types.ts";
import type { AiAsset, AiBom, AiBomOptions, AiCapability } from "./types.ts";

type Candidate = Omit<AiAsset, "id" | "fingerprint">;

const HIGH_RISK_CAPABILITIES = new Set<AiCapability>([
  "shell",
  "filesystem",
  "database",
  "secret-access",
  "mcp-tool"
]);

export function buildAiBom(files: DiffFile[], options: AiBomOptions): AiBom {
  const assets = dedupeAssets(files.filter((file) => !isIgnoredInventoryPath(file.path)).flatMap(extractAssetsFromFile));
  const providers = assets.filter((asset) => asset.kind === "provider");
  const models = assets.filter((asset) => asset.kind === "model");
  const prompts = assets.filter((asset) => asset.kind === "prompt");
  const agents = assets.filter((asset) => asset.kind === "agent");
  const tools = assets.filter((asset) => asset.kind === "tool");
  const vectorStores = assets.filter((asset) => asset.kind === "vector-store");
  const mcpServers = assets.filter((asset) => asset.kind === "mcp-server");
  const dataStores = assets.filter((asset) => asset.kind === "data-store");
  const highRiskCapabilities = uniqueCapabilities(
    assets.flatMap((asset) => asset.capabilities.filter((capability) => HIGH_RISK_CAPABILITIES.has(capability)))
  );

  return {
    tool: "vibeguard",
    schemaVersion: "vibeguard.aibom.v1",
    generatedAt: options.generatedAt ?? new Date().toISOString(),
    targetPath: options.targetPath,
    summary: {
      providers: providers.length,
      models: models.length,
      prompts: prompts.length,
      agents: agents.length,
      tools: tools.length,
      vectorStores: vectorStores.length,
      mcpServers: mcpServers.length,
      dataStores: dataStores.length,
      highRiskCapabilities
    },
    providers,
    models,
    prompts,
    agents,
    tools,
    vectorStores,
    mcpServers,
    dataStores
  };
}

function extractAssetsFromFile(file: DiffFile): AiAsset[] {
  const candidates: Candidate[] = [];
  const lines = file.allLines ?? file.addedLines;

  for (const line of lines) {
    const source = stripLine(line.content);
    if (!source.trim()) continue;

    const provider = detectProvider(source);
    if (provider) {
      candidates.push({
        kind: "provider",
        name: provider,
        file: file.path,
        line: line.line,
        confidence: "high",
        evidenceStrength: "direct",
        evidenceSource: "provider syntax",
        detectionMethod: "provider-syntax",
        capabilities: ["llm-call", "external-provider"],
        metadata: {}
      });
    }

    for (const model of detectModels(line.content, source)) {
      candidates.push({
        kind: "model",
        name: model,
        file: file.path,
        line: line.line,
        confidence: "high",
        evidenceStrength: "direct",
        evidenceSource: "model literal",
        detectionMethod: "model-literal",
        capabilities: ["llm-call"],
        metadata: {}
      });
    }

    const promptName = detectPrompt(source);
    if (promptName) {
      candidates.push({
        kind: "prompt",
        name: promptName,
        file: file.path,
        line: line.line,
        confidence: "medium",
        evidenceStrength: "direct",
        evidenceSource: "prompt variable assignment",
        detectionMethod: "prompt-variable",
        capabilities: ["prompt-control"],
        metadata: {}
      });
    }

    const agent = detectAgent(line.content, source);
    if (agent) {
      candidates.push({
        kind: "agent",
        name: agent.name,
        file: file.path,
        line: line.line,
        confidence: "medium",
        evidenceStrength: "direct",
        evidenceSource: "createAgent call",
        detectionMethod: "agent-constructor",
        capabilities: ["llm-call"],
        metadata: agent.toolNames.length ? { tools: agent.toolNames.join(",") } : {}
      });
    }

    for (const tool of detectToolReferences(source)) {
      candidates.push({
        kind: "tool",
        name: tool.name,
        file: file.path,
        line: line.line,
        confidence: "medium",
        evidenceStrength: "same-file",
        evidenceSource: "agent tools array",
        detectionMethod: "agent-tool-reference",
        capabilities: tool.capabilities,
        metadata: { source: "agent-tool-reference" }
      });
    }

    const tool = detectToolDefinition(source);
    if (tool) {
      candidates.push({
        kind: "tool",
        name: tool.name,
        file: file.path,
        line: line.line,
        confidence: "high",
        evidenceStrength: "direct",
        evidenceSource: "tool definition",
        detectionMethod: "tool-definition",
        capabilities: tool.capabilities,
        metadata: {}
      });
    }

    if (isVectorStoreUse(source)) {
      candidates.push({
        kind: "vector-store",
        name: vectorStoreName(source),
        file: file.path,
        line: line.line,
        confidence: "medium",
        evidenceStrength: "direct",
        evidenceSource: "vector store API usage",
        detectionMethod: "vector-store-usage",
        capabilities: ["vector-search"],
        metadata: {}
      });
    }

    if (/\b(prisma|sequelize|mongoose|db\.query|pool\.query|client\.query)\b/i.test(source)) {
      candidates.push({
        kind: "data-store",
        name: "application-database",
        file: file.path,
        line: line.line,
        confidence: "medium",
        evidenceStrength: "direct",
        evidenceSource: "data store API usage",
        detectionMethod: "data-store-usage",
        capabilities: ["database"],
        metadata: {}
      });
    }

    const mcpServer = detectMcpServer(file.path, line.content);
    if (mcpServer) {
      candidates.push({
        kind: "mcp-server",
        name: mcpServer,
        file: file.path,
        line: line.line,
        confidence: "high",
        evidenceStrength: "direct",
        evidenceSource: "MCP server config",
        detectionMethod: "mcp-config",
        capabilities: uniqueCapabilities(["mcp-tool", ...capabilitiesFromText(line.content)]),
        metadata: {}
      });
    }
  }

  return dedupeAssets(candidates.map((candidate) => withAssetId(candidate)));
}

function detectProvider(source: string): string | undefined {
  if (/\bOpenAI\b|openai\./i.test(source)) return "openai";
  if (/\bAnthropic\b|anthropic\./i.test(source)) return "anthropic";
  if (/\bGoogleGenerativeAI\b|gemini/i.test(source)) return "google";
  if (/\bAzureOpenAI\b/i.test(source)) return "azure-openai";
  if (/\bBedrockRuntime|bedrock/i.test(source)) return "aws-bedrock";
  return undefined;
}

function detectModels(rawSource: string, strippedSource: string): string[] {
  if (!/\b(model|modelName|from_pretrained)\b/.test(strippedSource)) return [];

  const models: string[] = [];
  const patterns = [
    /\bmodel\s*:\s*["']([^"']+)["']/g,
    /\bmodelName\s*:\s*["']([^"']+)["']/g,
    /\bfrom_pretrained\(\s*["']([^"']+)["']/g
  ];

  for (const pattern of patterns) {
    for (const match of rawSource.matchAll(pattern)) {
      models.push(match[1]);
    }
  }

  return [...new Set(models)];
}

function detectPrompt(source: string): string | undefined {
  if (!/\b(systemPrompt|developerPrompt|prompt)\b\s*=/.test(source)) return undefined;
  return variableName(source) ?? "prompt";
}

function detectAgent(rawSource: string, strippedSource: string): { name: string; toolNames: string[] } | undefined {
  if (!/\b(createAgent|initializeAgentExecutor|AgentExecutor|new Agent)\b/.test(strippedSource)) return undefined;
  return {
    name: /name\s*:\s*["']([^"']+)["']/.exec(rawSource)?.[1] ?? "agent",
    toolNames: toolNamesFromArray(strippedSource)
  };
}

function detectToolReferences(source: string): { name: string; capabilities: AiCapability[] }[] {
  return toolNamesFromArray(source).map((name) => ({
    name,
    capabilities: capabilitiesForToolName(name)
  }));
}

function detectToolDefinition(source: string): { name: string; capabilities: AiCapability[] } | undefined {
  const hasToolKeyword = /\b[\w$]*tools?\b/i.test(source) ||
    /\b(functions|function_call|tool_choice)\b/i.test(source);
  const hasToolShape = /\b(execute|handler|callback|func)\s*:/.test(source) ||
    /\b(tool|DynamicTool|StructuredTool)\s*\(/i.test(source) ||
    /\btools?\s*[:=]/i.test(source);
  if (!hasToolKeyword || !hasToolShape) return undefined;

  const name = variableName(source) ?? "tool";
  const capabilities = uniqueCapabilities([...capabilitiesForToolName(name), ...capabilitiesFromText(source)]);
  if (capabilities.length === 0 && !/\bexecute|handler|callback|func\b/.test(source)) return undefined;

  return { name, capabilities: capabilities.length ? capabilities : ["network"] };
}

function toolNamesFromArray(source: string): string[] {
  const match = /\btools\s*:\s*\[([^\]]+)\]/i.exec(source);
  if (!match) return [];

  return match[1]
    .split(",")
    .map((value) => value.trim())
    .filter((value) => /^[A-Za-z_$][\w$]*$/.test(value));
}

function capabilitiesForToolName(name: string): AiCapability[] {
  return capabilitiesFromText(name);
}

function capabilitiesFromText(source: string): AiCapability[] {
  const capabilities = new Set<AiCapability>();
  if (/\b(shell|run_shell|exec|spawn|terminal|command)\b/i.test(source)) capabilities.add("shell");
  if (/\b(fs\.|readFile|writeFile|filesystem|file_path|path)\b/i.test(source)) capabilities.add("filesystem");
  if (/\b(fetch|axios|http|https|request|url)\b/i.test(source)) capabilities.add("network");
  if (/\b(prisma|sequelize|mongoose|sql|db\.|database|(?:pool|client)\.query)\b/i.test(source)) capabilities.add("database");
  if (/\b(vector|embedding|retriever|similaritySearch)\b/i.test(source)) capabilities.add("vector-search");
  if (/\b(apiKey|secret|token|process\.env)\b/i.test(source)) capabilities.add("secret-access");
  return [...capabilities].sort();
}

function isVectorStoreUse(source: string): boolean {
  return /\b(vectorStore|retriever|similaritySearch|embedding|pinecone|weaviate|qdrant|chroma)\b/i.test(source);
}

function vectorStoreName(source: string): string {
  if (/pinecone/i.test(source)) return "pinecone";
  if (/weaviate/i.test(source)) return "weaviate";
  if (/qdrant/i.test(source)) return "qdrant";
  if (/chroma/i.test(source)) return "chroma";
  return "vector-store";
}

function detectMcpServer(path: string, rawSource: string): string | undefined {
  if (!path.endsWith("mcp.json")) return undefined;

  const name = /"([^"]+)"\s*:\s*\{/.exec(rawSource)?.[1];
  if (!name || name === "mcpServers") return undefined;
  return name;
}

function isIgnoredInventoryPath(path: string): boolean {
  return /(^|\/)(node_modules|dist|build|coverage|\.next|\.git|\.worktrees)(\/|$)/.test(path);
}

function variableName(source: string): string | undefined {
  return /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\b/.exec(source)?.[1];
}

function stripLine(line: string): string {
  let output = "";
  let quote: string | undefined;
  let escaped = false;

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    const next = line[index + 1];

    if (!quote && char === "/" && next === "/") break;
    if (!quote && char === "#") break;

    if ((char === "\"" || char === "'" || char === "`") && !escaped) {
      quote = quote === char ? undefined : quote ?? char;
      output += " ";
      escaped = false;
      continue;
    }

    output += quote ? " " : char;
    escaped = char === "\\" && !escaped;
  }

  return output;
}

function dedupeAssets(assets: AiAsset[]): AiAsset[] {
  const byKey = new Map<string, AiAsset>();

  for (const asset of assets) {
    const key = assetKey(asset);
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, asset);
      continue;
    }

    byKey.set(key, {
      ...existing,
      line: Math.min(existing.line, asset.line),
      confidence: higherConfidence(existing.confidence, asset.confidence),
      evidenceStrength: strongerEvidence(existing.evidenceStrength, asset.evidenceStrength),
      evidenceSource: strongerEvidence(existing.evidenceStrength, asset.evidenceStrength) === existing.evidenceStrength ? existing.evidenceSource : asset.evidenceSource,
      detectionMethod: strongerEvidence(existing.evidenceStrength, asset.evidenceStrength) === existing.evidenceStrength ? existing.detectionMethod : asset.detectionMethod,
      relatedLocations: uniqueRelatedLocations([...(existing.relatedLocations ?? []), ...(asset.relatedLocations ?? []), { file: asset.file, line: asset.line, label: asset.detectionMethod }]),
      capabilities: uniqueCapabilities([...existing.capabilities, ...asset.capabilities]),
      metadata: { ...asset.metadata, ...existing.metadata }
    });
  }

  return [...byKey.values()]
    .map((asset) => withAssetId(asset))
    .sort((left, right) => `${left.kind}:${left.file}:${left.line}:${left.name}`.localeCompare(`${right.kind}:${right.file}:${right.line}:${right.name}`));
}

function assetKey(asset: Pick<AiAsset, "kind" | "name" | "file">): string {
  return `${asset.kind}\0${asset.file}\0${asset.name.toLowerCase()}`;
}

function withAssetId(asset: Candidate): AiAsset {
  const hash = createHash("sha256")
    .update(assetKey(asset))
    .digest("hex")
    .slice(0, 12);
  const fingerprintSource = [
    asset.kind,
    normalizeAssetName(asset.name),
    [...asset.capabilities].sort().join(","),
    asset.file,
    String(asset.line)
  ].join("|");
  const fingerprint = createHash("sha256")
    .update(fingerprintSource)
    .digest("hex")
    .slice(0, 16);

  return {
    ...asset,
    id: `${asset.kind}:${hash}`,
    fingerprint
  };
}

export function normalizeAssetName(name: string): string {
  return name.trim().toLowerCase();
}

function higherConfidence(left: AiAsset["confidence"], right: AiAsset["confidence"]): AiAsset["confidence"] {
  const rank = { low: 1, medium: 2, high: 3 };
  return rank[left] >= rank[right] ? left : right;
}

function strongerEvidence(left: EvidenceStrength, right: EvidenceStrength): EvidenceStrength {
  const rank = {
    unknown: 0,
    "repository-inferred": 1,
    "same-module": 2,
    "same-file": 3,
    direct: 4
  };
  return rank[left] >= rank[right] ? left : right;
}

function uniqueRelatedLocations(locations: NonNullable<AiAsset["relatedLocations"]>): NonNullable<AiAsset["relatedLocations"]> {
  return [...new Map(locations.map((location) => [`${location.file}\0${location.line}\0${location.label ?? ""}`, location])).values()];
}

function uniqueCapabilities(capabilities: AiCapability[]): AiCapability[] {
  return [...new Set(capabilities)].sort();
}
