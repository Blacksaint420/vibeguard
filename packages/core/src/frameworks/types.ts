import type { FrameworkId, FrameworkMapping, GrcRisk, RuleMetadata } from "../types.ts";

export type FrameworkCatalogEntry = {
  id: FrameworkId;
  name: string;
  sourceVersion: string;
  sourceUrl: string;
};

export type RuleEnterpriseContext = {
  rule: RuleMetadata;
  frameworks: FrameworkMapping[];
  risk: GrcRisk;
  controlGaps: string[];
};
