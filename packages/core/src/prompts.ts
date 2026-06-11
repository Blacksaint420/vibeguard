export function generateAiFixPrompt(input: {
  ruleId: string;
  file: string;
  line: number;
  snippet: string;
  why: string;
  suggestedFix: string;
  testSuggestion: string;
}): string {
  return [
    `You are fixing a VibeGuard finding (${input.ruleId}) in ${input.file}:${input.line}.`,
    `Risk: ${input.why}`,
    `Relevant changed code: ${input.snippet}`,
    `Make this change: ${input.suggestedFix}`,
    `Add or update tests: ${input.testSuggestion}`,
    "Keep the fix minimal and do not introduce network calls or broad refactors."
  ].join(" ");
}

