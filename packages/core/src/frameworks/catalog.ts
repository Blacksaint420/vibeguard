import type { FrameworkCatalogEntry } from "./types.ts";

export const FRAMEWORK_CATALOG: FrameworkCatalogEntry[] = [
  {
    id: "owasp-llm-2025",
    name: "OWASP Top 10 for LLM Applications",
    sourceVersion: "2025",
    sourceUrl: "https://genai.owasp.org/llm-top-10/"
  },
  {
    id: "nist-ai-rmf",
    name: "NIST AI Risk Management Framework",
    sourceVersion: "AI RMF 1.0 + GenAI Profile",
    sourceUrl: "https://www.nist.gov/itl/ai-risk-management-framework"
  },
  {
    id: "mitre-atlas",
    name: "MITRE ATLAS",
    sourceVersion: "2026 public knowledge base",
    sourceUrl: "https://atlas.mitre.org/"
  },
  {
    id: "google-saif",
    name: "Google Secure AI Framework",
    sourceVersion: "SAIF 2.0",
    sourceUrl: "https://saif.google/"
  }
];
