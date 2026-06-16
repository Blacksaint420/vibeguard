import type { RuleMetadata, ScannerName } from "./types.ts";

export const BUILT_IN_RULE_VERSION = "2026.06.11";

export type BuiltInRuleDefinition = RuleMetadata & {
  why?: string;
  fix?: string;
};

function builtInRule(
  id: string,
  name: string,
  scanner: ScannerName,
  why?: string,
  fix?: string
): BuiltInRuleDefinition {
  return {
    id,
    name,
    version: BUILT_IN_RULE_VERSION,
    stability: "stable",
    scanner,
    why,
    fix
  };
}

const BUILT_IN_RULE_LIST: BuiltInRuleDefinition[] = [
  builtInRule(
    "ai-agent-shell-tool-no-approval",
    "Agent tool exposes shell execution without approval",
    "ai",
    "Agent tools that expose shell execution need explicit approval and constrained arguments because model-selected tool calls are attacker-influenceable.",
    "Remove shell-capable agent tools or require human approval, strict command allowlists, and structured arguments before execution."
  ),
  builtInRule(
    "ai-rag-query-without-filter",
    "RAG retrieval query has no visible authorization filter",
    "ai",
    "RAG retrieval should be scoped by server-side authorization context so user queries cannot search across protected document boundaries.",
    "Add a server-derived metadata filter, tenant namespace, or authorization scope to the retrieval call."
  ),
  builtInRule(
    "ai-unbounded-token-request",
    "LLM request uses excessive token budget",
    "ai",
    "LLM token budgets should have practical server-side ceilings instead of unbounded or extreme per-request limits.",
    "Clamp token budgets to a documented maximum appropriate for the use case and reject Infinity or unusually high values."
  ),
  builtInRule(
    "ai-model-trust-remote-code",
    "Model loading trusts remote code",
    "ai",
    "Model artifacts are part of the software supply chain; trusting remote code turns model loading into code execution.",
    "Disable trust_remote_code, pin reviewed model revisions, and vendor or audit any required custom model code."
  ),
  builtInRule(
    "llm01-direct-prompt-injection",
    "User-controlled content enters system prompt",
    "code",
    "Untrusted request data in a privileged LLM instruction channel can override intended system or developer instructions.",
    "Keep system/developer prompts static and pass user content as separate, clearly delimited user data."
  ),
  builtInRule(
    "llm05-output-exec",
    "LLM output reaches code execution sink",
    "code",
    "LLM-generated text is untrusted data and can be steered by prompts into unsafe code or command output.",
    "Replace execution of model text with constrained schemas, allowlists, and approval for dangerous actions."
  ),
  builtInRule("llm07-system-prompt-leak", "System prompt returned to caller", "code"),
  builtInRule("llm10-user-controlled-token-budget", "User controls LLM token budget", "code"),
  builtInRule("llm06-auto-tool-dangerous-sink", "Autonomous LLM tool path reaches dangerous sink", "code"),
  builtInRule("llm04-untrusted-vector-ingestion", "Untrusted request content enters vector store", "code"),
  builtInRule("llm08-user-controlled-vector-filter", "User controls vector search filter", "code"),
  builtInRule(
    "js-eval",
    "JavaScript eval usage",
    "code",
    "Dynamic code execution can run attacker-controlled input and bypass normal review boundaries.",
    "Replace eval with explicit parsing, schema validation, or a narrow command dispatch table."
  ),
  builtInRule("js-function-constructor", "Function constructor usage", "code"),
  builtInRule("js-sql-template-interpolation", "SQL query uses template interpolation", "code"),
  builtInRule("js-prisma-raw-unsafe", "Prisma unsafe raw query", "code"),
  builtInRule("js-child-process-exec-user-input", "child_process.exec with request-derived input", "code"),
  builtInRule("js-log-secret", "Secret or authorization value logged", "code"),
  builtInRule("js-jwt-decode-no-verify", "JWT decoded without verification", "code"),
  builtInRule("js-permissive-cors", "Permissive CORS", "code"),
  builtInRule("js-insecure-cookie", "Insecure cookie options", "code"),
  builtInRule("js-tls-disabled", "TLS verification disabled", "code"),
  builtInRule("js-ssrf-request-input", "Outbound request uses request-derived URL", "code"),
  builtInRule("js-nextjs-ssrf-query-fetch", "Next.js server-side fetch uses query input", "code"),
  builtInRule("js-path-traversal", "Filesystem access uses request-derived path", "code"),
  builtInRule("js-weak-random-token", "Math.random used for token generation", "code"),
  builtInRule("js-supabase-service-role-client", "Supabase service role key used in application code", "code"),
  builtInRule("js-express-route-no-obvious-auth", "Express route has no obvious auth middleware", "code"),
  builtInRule("py-eval-exec", "Python eval or exec usage", "code"),
  builtInRule("py-sql-string-format", "SQL query uses string formatting", "code"),
  builtInRule("py-subprocess-shell-user-input", "subprocess shell=True with user input", "code"),
  builtInRule("py-pickle-loads", "pickle.loads usage", "code"),
  builtInRule(
    "py-yaml-unsafe-load",
    "yaml.load without SafeLoader",
    "code",
    "Unsafe YAML loading can instantiate arbitrary objects from attacker-controlled YAML.",
    "Use yaml.safe_load or specify SafeLoader."
  ),
  builtInRule("py-requests-verify-false", "requests disables TLS verification", "code"),
  builtInRule("py-debug-true", "Debug mode enabled", "code"),
  builtInRule("py-weak-random-token", "random module used for token generation", "code"),
  builtInRule("py-jwt-no-verify", "JWT verification disabled", "code"),
  builtInRule("py-permissive-cors", "Permissive CORS", "code"),
  builtInRule("py-django-csrf-exempt", "Django CSRF protection disabled", "code"),
  builtInRule("py-flask-route-no-obvious-auth", "Flask route has no obvious auth guard", "code"),
  builtInRule("firebase-public-rules", "Firebase rules allow public access", "code"),
  builtInRule("secret-private-key", "Private key material", "secrets"),
  builtInRule("secret-aws-access-key", "AWS access key", "secrets"),
  builtInRule(
    "secret-github-token",
    "GitHub token in changed code",
    "secrets",
    "Committed access tokens can be harvested from git history and used outside your environment.",
    "Revoke the token, move secrets to a secret manager or environment variable, and rotate credentials."
  ),
  builtInRule("secret-slack-token", "Slack token", "secrets"),
  builtInRule("secret-authorization-header", "Authorization header", "secrets"),
  builtInRule("pii-us-ssn", "US Social Security number", "secrets"),
  builtInRule("pii-credit-card", "Credit card number", "secrets"),
  builtInRule("dep-lockfile-without-manifest", "Lockfile changed without manifest change", "dependencies"),
  builtInRule("dep-lockfile-install-script", "Resolved package has install script", "dependencies"),
  builtInRule("dep-lockfile-insecure-resolved-url", "Lockfile resolves package over HTTP", "dependencies"),
  builtInRule("dep-vulnerable-package", "Vulnerable dependency", "dependencies"),
  builtInRule("dep-install-script", "Package lifecycle install script", "dependencies"),
  builtInRule("dep-new-or-changed", "New or changed dependency", "dependencies"),
  builtInRule(
    "dep-broad-version-range",
    "Broad dependency version range",
    "dependencies",
    "Broad ranges can pull unreviewed code in future installs.",
    "Pin the dependency or use a narrowly reviewed range plus lockfile review."
  ),
  builtInRule("dep-version-downgrade", "Dependency version downgrade", "dependencies"),
  builtInRule("dep-suspicious-package-name", "Suspicious package name", "dependencies"),
  builtInRule(
    "docker-base-latest",
    "Docker base image uses latest",
    "docker",
    "The latest tag is mutable, so builds can change without a code review.",
    "Pin the image to an explicit version or immutable digest."
  ),
  builtInRule(
    "docker-base-unpinned",
    "Docker base image is unpinned",
    "docker",
    "Unpinned image references can resolve to different code over time.",
    "Pin the image to a version tag or immutable digest."
  ),
  builtInRule(
    "gha-mutable-action-ref",
    "GitHub Action uses mutable reference",
    "actions",
    "Mutable action refs can change after review and alter CI behavior.",
    "Pin actions to a full commit SHA."
  ),
  builtInRule("gha-write-all-permissions", "GitHub workflow grants write-all permissions", "actions"),
  builtInRule("gha-pull-request-target", "pull_request_target workflow trigger", "actions"),
  builtInRule("sensitive-file-change", "Sensitive file changed", "sensitive-files")
].map((rule) => Object.freeze(rule));

export const BUILT_IN_RULES: Readonly<Record<string, Readonly<BuiltInRuleDefinition>>> = Object.freeze(
  Object.fromEntries(BUILT_IN_RULE_LIST.map((rule) => [rule.id, rule]))
);

export function builtInRuleDefinition(idOrFindingId: string): BuiltInRuleDefinition | undefined {
  const exact = BUILT_IN_RULES[idOrFindingId];
  if (exact) return { ...exact };

  const rule = BUILT_IN_RULE_LIST.find((candidate) => idOrFindingId.startsWith(`${candidate.id}:`));
  return rule ? { ...rule } : undefined;
}

export function builtInRuleMetadata(idOrFindingId: string): RuleMetadata | undefined {
  const rule = builtInRuleDefinition(idOrFindingId);
  if (!rule) return undefined;
  return {
    id: rule.id,
    name: rule.name,
    version: rule.version,
    stability: rule.stability,
    scanner: rule.scanner
  };
}
