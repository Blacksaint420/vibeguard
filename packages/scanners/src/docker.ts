import type { DiffFile, Finding } from "../../core/src/types.ts";
import { scannerFinding } from "./utils.ts";

export function runDockerfileScanner(files: DiffFile[]): Finding[] {
  const findings: Finding[] = [];

  for (const file of files.filter((candidate) => /(^|\/)Dockerfile(\..+)?$/.test(candidate.path))) {
    for (const line of file.addedLines) {
      const from = /^FROM\s+([^\s]+)(?:\s+AS\s+\w+)?/i.exec(line.content.trim());
      if (!from) continue;

      const image = from[1];
      if (/:latest$/i.test(image)) {
        findings.push(scannerFinding({
          ruleId: "docker-base-latest",
          title: "Docker base image uses latest",
          severity: "medium",
          confidence: "medium",
          riskScore: 82,
          file: file.path,
          line: line.line,
          snippet: line.content,
          evidence: "Dockerfile uses a mutable latest base image tag.",
          attackPath: "Base image tag changes upstream -> build pulls new image -> unreviewed code enters runtime.",
          impact: "Mutable images can silently change the deployed LLM application environment.",
          why: "The latest tag is mutable and can change builds without a code review.",
          suggestedFix: "Pin the base image to a reviewed version or immutable digest.",
          testSuggestion: "Rebuild the image from a clean cache and verify the pinned base digest."
        }));
      } else if (!image.includes(":") && !image.includes("@sha256:")) {
        findings.push(scannerFinding({
          ruleId: "docker-base-unpinned",
          title: "Docker base image is unpinned",
          severity: "medium",
          confidence: "medium",
          riskScore: 60,
          file: file.path,
          line: line.line,
          snippet: line.content,
          evidence: "Dockerfile uses an image without a version tag or digest.",
          attackPath: "Unpinned image resolves differently over time -> build consumes unreviewed base image.",
          impact: "The runtime environment can drift and inherit vulnerable or malicious components.",
          why: "Unpinned image references can resolve to different code over time.",
          suggestedFix: "Pin the image to a version tag or immutable digest.",
          testSuggestion: "Verify the build uses the expected base image digest."
        }));
      }
    }
  }

  return findings;
}
