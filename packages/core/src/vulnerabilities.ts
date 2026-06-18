import type { Severity, Vulnerability, VulnerabilityProvider } from "./types.ts";

export type VulnerabilityProviderName = "null" | "mock" | "osv";

const OSV_QUERY_TIMEOUT_MS = 10_000;

export type VulnerabilityProviderOptions = {
  timeoutMs?: number;
};

export function createVulnerabilityProvider(name: VulnerabilityProviderName, options: VulnerabilityProviderOptions = {}): VulnerabilityProvider {
  if (name === "mock") return mockVulnerabilityProvider;
  if (name === "osv") return createOsvVulnerabilityProvider(options);
  return nullVulnerabilityProvider;
}

export const nullVulnerabilityProvider: VulnerabilityProvider = {
  name: "null",
  async query() {
    return [];
  }
};

export const mockVulnerabilityProvider: VulnerabilityProvider = {
  name: "mock",
  async query(packageName: string, version?: string) {
    if (packageName !== "vulnerable-package") return [];
    return [{
      id: "MOCK-2026-0001",
      packageName,
      installedVersion: version,
      severity: "high",
      summary: "Mock vulnerability used for local VibeGuard tests."
    }];
  }
};

export function createOsvVulnerabilityProvider(options: VulnerabilityProviderOptions = {}): VulnerabilityProvider {
  return {
    name: "osv",
    async query(packageName: string, version?: string, ecosystem?: string) {
      const response = await fetch("https://api.osv.dev/v1/query", {
        method: "POST",
        headers: { "content-type": "application/json" },
        signal: AbortSignal.timeout(options.timeoutMs ?? OSV_QUERY_TIMEOUT_MS),
        body: JSON.stringify({
          package: {
            name: packageName,
            ecosystem: ecosystem ?? "npm"
          },
          ...(version ? { version } : {})
        })
      });

      if (!response.ok) {
        throw new Error(`OSV query failed for ${packageName}: HTTP ${response.status}`);
      }

      const body = await response.json() as {
        vulns?: Array<{ id?: string; summary?: string; database_specific?: { severity?: string } }>;
      };

      return (body.vulns ?? []).map((vuln): Vulnerability => ({
        id: vuln.id ?? "OSV-UNKNOWN",
        packageName,
        installedVersion: version,
        severity: normalizeSeverity(vuln.database_specific?.severity),
        summary: vuln.summary ?? "OSV reported a vulnerability for this dependency."
      }));
    }
  };
}

function normalizeSeverity(value: string | undefined): Severity {
  const normalized = value?.toLowerCase();
  if (normalized === "critical") return "critical";
  if (normalized === "high") return "high";
  if (normalized === "medium" || normalized === "moderate") return "medium";
  return "low";
}
