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
    `You are fixing a VibeGuard finding (${asUserContent("rule", input.ruleId)}) in ${asUserContent("file", input.file)}:${input.line}.`,
    `Risk: ${asUserContent("why", input.why)}`,
    `Relevant changed code: ${asUserContent("snippet", input.snippet)}`,
    `Make this change: ${asUserContent("suggestedFix", input.suggestedFix)}`,
    `Add or update tests: ${asUserContent("testSuggestion", input.testSuggestion)}`,
    "Keep the fix minimal and do not introduce network calls or broad refactors."
  ].join(" ");
}

function asUserContent(label: string, value: string): string {
  return `<user_content label="${escapeAttribute(label)}">${escapeUserContent(value)}</user_content>`;
}

function escapeUserContent(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function escapeAttribute(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/"/g, "&quot;");
}
