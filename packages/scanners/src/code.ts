import type { DiffFile, Finding } from "../../core/src/types.ts";
import { owaspCategory } from "../../core/src/owasp.ts";
import { maskSecretsInText } from "./secrets.ts";
import { isJavaScriptFile, isPythonFile, scannerFinding } from "./utils.ts";

type Rule = {
  id: string;
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  confidence: "low" | "medium" | "high";
  riskScore: number;
  pattern: RegExp;
  stripStrings?: boolean;
  unless?: RegExp;
  owasp?: ReturnType<typeof owaspCategory>;
  evidence?: string;
  attackPath?: string;
  impact?: string;
  requiresFilePattern?: RegExp;
  why: string;
  fix: string;
  test: string;
};

const JS_RULES: Rule[] = [
  rule("llm01-direct-prompt-injection", "User-controlled content enters system prompt", "critical", "high", 96, /role\s*:\s*["'](?:system|developer)["'][^}\n]*content\s*:[^}\n]*(req\.|request\.|ctx\.request|params|query|body)/i, "Untrusted request data is inserted into a privileged LLM instruction channel.", "Keep system/developer prompts static. Put user content in a separate user message with clear delimiters and policy checks.", "Add a test that prompt-injection strings in request data cannot override the system instruction.", false, {
    owasp: owaspCategory("LLM01:2025"),
    evidence: "Request-controlled data is interpolated into a system or developer prompt.",
    attackPath: "Attacker controls request data -> data becomes privileged LLM instruction -> model follows attacker instruction.",
    impact: "The attacker can override intended instructions, bypass guardrails, or steer tool use."
  }),
  rule("llm05-output-exec", "LLM output reaches code execution sink", "critical", "high", 98, /\b(eval|exec|spawn|execFile)\s*\([^)]*(completion|response|llm|model|message\.content|choices\s*\[|output_text|tool_calls)/i, "LLM-generated text is treated as executable code or a shell command.", "Treat model output as untrusted data. Replace execution with a constrained command schema, allowlist, and human approval for dangerous actions.", "Add a test where the model returns shell metacharacters or JavaScript and prove it is rejected.", true, {
    owasp: owaspCategory("LLM05:2025"),
    evidence: "Model output is passed to eval, exec, spawn, or execFile.",
    attackPath: "Attacker prompts the model -> model emits code or command text -> application executes it.",
    impact: "This can become remote code execution in the application runtime."
  }),
  rule("llm07-system-prompt-leak", "System prompt returned to caller", "high", "high", 86, /\b(res\.(send|json)|return)\s*\([^)]*(SYSTEM_PROMPT|systemPrompt|developerPrompt|guardrailPrompt)/i, "The application returns privileged prompt text to the caller.", "Do not expose system or developer prompts. Return only user-safe response metadata.", "Add a test proving prompt constants are never present in API responses.", false, {
    owasp: owaspCategory("LLM07:2025"),
    evidence: "A response path includes a system or developer prompt variable.",
    attackPath: "Caller invokes endpoint -> endpoint returns privileged prompt material -> attacker learns guardrails and secrets embedded in prompts.",
    impact: "Prompt leakage makes bypasses easier and can disclose sensitive operational details."
  }),
  rule("llm10-user-controlled-token-budget", "User controls LLM token budget", "high", "high", 84, /\b(max_tokens|max_completion_tokens|maxOutputTokens)\s*:\s*(req\.|request\.|ctx\.request|params|query|body)/i, "Request-controlled token limits let callers drive model cost and latency.", "Enforce server-side token ceilings and ignore client-supplied token budgets unless clamped to a safe maximum.", "Add a test proving large client token values are capped before the LLM call.", false, {
    owasp: owaspCategory("LLM10:2025"),
    evidence: "An LLM token budget is assigned from request-controlled data.",
    attackPath: "Attacker supplies large token limit -> application forwards it to model call -> model consumes excessive tokens.",
    impact: "This can increase cost, degrade availability, or exhaust rate limits."
  }),
  rule("llm06-auto-tool-dangerous-sink", "Autonomous LLM tool path reaches dangerous sink", "critical", "high", 96, /\b(exec|spawn|execFile|writeFile|writeFileSync|unlink|rm)\s*\([^)]*(toolCall|tool_call|function\.arguments|arguments)/i, "Automatic tool use is connected to command or filesystem capabilities.", "Require explicit approval and strict schemas for dangerous tools; route commands through allowlisted operations only.", "Add tests proving tool calls cannot execute shell commands or write files without approval.", false, {
    owasp: owaspCategory("LLM06:2025"),
    evidence: "A dangerous sink consumes tool-call arguments while the file enables automatic tool choice.",
    attackPath: "Model selects tool autonomously -> tool arguments reach command or filesystem sink -> application performs unintended action.",
    impact: "This can allow autonomous command execution, file writes, or destructive operations.",
    requiresFilePattern: /\btool_choice\s*:\s*["']auto["']|\btoolChoice\s*:\s*["']auto["']|\bmessage\.tool_calls\b|\btool_calls\b/i
  }),
  rule("llm04-untrusted-vector-ingestion", "Untrusted request content enters vector store", "high", "high", 86, /\b(addDocuments|addVectors|upsert|insert)\s*\([^)]*(req\.|request\.|ctx\.request|params|query|body)/i, "Request-controlled content is written directly into an embedding or vector store.", "Validate provenance, tenant scope, size, and content policy before indexing documents used for retrieval.", "Add a test proving untrusted documents are rejected or quarantined before vector ingestion.", false, {
    owasp: owaspCategory("LLM04:2025"),
    evidence: "Request-controlled content is passed into a vector-store ingestion method.",
    attackPath: "Attacker submits content -> content is embedded and indexed -> later retrieval injects attacker content into prompts.",
    impact: "This can poison RAG context and influence future model responses."
  }),
  rule("llm08-user-controlled-vector-filter", "User controls vector search filter", "high", "high", 82, /\b(query|similaritySearch|similaritySearchWithScore|search)\s*\([^)]*(filter|where)\s*:\s*(req\.|request\.|ctx\.request|params|query|body)/i, "Request-controlled vector search filters can bypass retrieval boundaries.", "Build vector filters server-side from authenticated tenant and authorization context; do not pass raw request filters.", "Add tests proving callers cannot query another tenant or restricted collection through metadata filters.", false, {
    owasp: owaspCategory("LLM08:2025"),
    evidence: "A vector query metadata filter is assigned from request-controlled data.",
    attackPath: "Attacker supplies metadata filter -> vector store uses attacker filter -> retrieval crosses intended data boundary.",
    impact: "This can disclose unauthorized embeddings, documents, or tenant data."
  }),
  rule("js-eval", "JavaScript eval usage", "high", "high", 90, /\beval\s*\(/i, "Dynamic code execution can run attacker-controlled input.", "Replace eval with a safe parser, explicit mapping, or validated command dispatch.", "Add a test proving untrusted input is rejected instead of executed.", true, {
    evidence: "The code executes a string dynamically with eval.",
    attackPath: "Untrusted text reaches eval -> runtime treats it as JavaScript.",
    impact: "This can execute attacker-controlled code in the application process.",
    unless: /\b(eval|exec|spawn|execFile)\s*\([^)]*(completion|response|llm|model|message\.content|choices\s*\[|output_text|tool_calls)/i
  }),
  rule("js-function-constructor", "Function constructor usage", "high", "high", 88, /(^|[^\w.])(?:new\s+)?Function\s*\(/, "The Function constructor executes strings as code.", "Replace dynamic function construction with explicit functions or a constrained expression parser.", "Add a test for a malicious expression string.", true, {
    evidence: "The code constructs executable JavaScript from a string.",
    attackPath: "Untrusted text reaches Function constructor -> runtime compiles and executes it.",
    impact: "This can execute attacker-controlled code in the application process."
  }),
  rule("js-sql-template-interpolation", "SQL query uses template interpolation", "high", "high", 86, /`[^`]*\b(SELECT\b[^`]*\bFROM\b|INSERT\b[^`]*\bINTO\b|UPDATE\b[^`]*\bSET\b|DELETE\b[^`]*\bFROM\b)[^`]*\$\{/i, "Interpolating values into SQL can allow injection.", "Use parameterized queries or prepared statements.", "Add a test with quote characters in user input.", false, {
    evidence: "A SQL statement is built with template interpolation.",
    attackPath: "Attacker controls interpolated value -> value changes SQL syntax -> database executes attacker-selected query logic.",
    impact: "This can expose, modify, or delete application data."
  }),
  rule("js-prisma-raw-unsafe", "Prisma unsafe raw query", "high", "high", 88, /\.\$(queryRawUnsafe|executeRawUnsafe)\s*\(/i, "Prisma unsafe raw query APIs execute interpolated SQL and can allow injection.", "Use parameterized Prisma queries, $queryRaw tagged templates, or model APIs.", "Add a test proving user input is bound as a parameter.", false, {
    evidence: "Prisma unsafe raw query API is used.",
    attackPath: "Untrusted value reaches raw SQL API -> database treats it as SQL syntax.",
    impact: "This can become SQL injection against application data."
  }),
  rule("js-child-process-exec-user-input", "child_process.exec with request-derived input", "critical", "high", 96, /\bexec\s*\([^)]*(req\.|request\.|ctx\.request|params|query|body|input)/i, "Shell execution with user-controlled input can lead to command injection.", "Use execFile or spawn with an argument array and strict allowlists.", "Add a test that shell metacharacters are treated as data.", false, {
    evidence: "Request-derived data is passed to child_process.exec.",
    attackPath: "Attacker controls request value -> value reaches shell command string -> shell interprets metacharacters.",
    impact: "This can execute arbitrary commands on the application host."
  }),
  rule("js-log-secret", "Secret or authorization value logged", "medium", "medium", 55, /console\.(log|warn|error|info)\([^)]*(authorization|password|secret|token|api[_-]?key)/i, "Logs often outlive requests and can expose credentials.", "Remove the secret from logs or log only non-sensitive metadata.", "Add a test or lint case ensuring sensitive headers are redacted.", false, {
    owasp: owaspCategory("LLM02:2025"),
    evidence: "A log statement references a credential-bearing value.",
    attackPath: "Secret is written to logs -> logs are retained or exported -> unauthorized reader obtains credential.",
    impact: "Leaked credentials can allow unauthorized access to model, cloud, or application resources."
  }),
  rule("js-jwt-decode-no-verify", "JWT decoded without verification", "high", "high", 84, /\bjwt\.decode\s*\(|verify\s*:\s*false/i, "Decoded JWTs are not trusted unless their signature and claims are verified.", "Use JWT verification with expected issuer, audience, algorithm, and expiry checks.", "Add a test that a tampered token is rejected.", false, {
    evidence: "JWT claims are decoded or verification is disabled.",
    attackPath: "Attacker supplies tampered token -> application trusts unverified claims.",
    impact: "This can bypass authentication or authorization decisions."
  }),
  rule("js-permissive-cors", "Permissive CORS", "medium", "medium", 60, /cors\s*\([^)]*origin\s*:\s*["']\*["']|Access-Control-Allow-Origin["']?\s*,\s*["']\*["']/i, "Wildcard CORS can expose authenticated APIs to untrusted origins.", "Allowlist expected origins and avoid credentials with wildcard origins.", "Add a test for rejected untrusted origins."),
  rule("js-insecure-cookie", "Insecure cookie options", "high", "medium", 78, /(res\.cookie|cookie)\([^)]*(secure\s*:\s*false|httpOnly\s*:\s*false|sameSite\s*:\s*["']none["'])/i, "Missing secure cookie controls can expose session data.", "Set secure, httpOnly, and an appropriate SameSite policy for session cookies.", "Add a test that session cookies include secure attributes.", false, {
    evidence: "Cookie options explicitly disable a security attribute.",
    attackPath: "Browser stores weak session cookie -> attacker steals or sends it cross-site.",
    impact: "This can expose session tokens or enable session abuse."
  }),
  rule("js-tls-disabled", "TLS verification disabled", "high", "high", 88, /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|rejectUnauthorized\s*:\s*false/i, "Disabling TLS verification allows machine-in-the-middle attacks.", "Remove the override and configure trusted certificates explicitly.", "Add a test that HTTPS clients use certificate validation.", false, {
    evidence: "TLS certificate verification is disabled.",
    attackPath: "Application connects over HTTPS without certificate validation -> network attacker impersonates service.",
    impact: "This can expose prompts, model outputs, credentials, or application data in transit."
  }),
  rule("js-ssrf-request-input", "Outbound request uses request-derived URL", "high", "medium", 76, /\b(fetch|axios(?:\.\w+)?)\s*\([^)]*(req\.|request\.|ctx\.request|params|query|body)/i, "Fetching request-controlled URLs can enable SSRF.", "Validate destination hosts against an allowlist and block internal networks.", "Add tests for blocked loopback and metadata-service URLs."),
  rule("js-nextjs-ssrf-query-fetch", "Next.js server-side fetch uses query input", "high", "medium", 78, /getServerSideProps.*\bfetch\s*\([^)]*(context\.query|searchParams|params\.)/i, "Next.js server-side data loaders can turn query-controlled URLs into SSRF.", "Resolve destinations through an allowlist and block internal network ranges.", "Add tests for blocked loopback and metadata-service URLs."),
  rule("js-path-traversal", "Filesystem access uses request-derived path", "high", "medium", 76, /\b(readFile|readFileSync|createReadStream|writeFile|writeFileSync|sendFile)\s*\([^)]*(req\.|request\.|params|query|body|\.\.)/i, "Request-controlled filesystem paths can allow path traversal.", "Resolve paths under an allowed base directory and reject traversal.", "Add tests for ../ traversal and absolute paths.", false, {
    evidence: "Filesystem API receives request-derived path data.",
    attackPath: "Attacker controls path value -> value escapes intended directory -> filesystem reads or writes unintended file.",
    impact: "This can disclose source, credentials, model artifacts, or overwrite application files."
  }),
  rule("js-weak-random-token", "Math.random used for token generation", "medium", "high", 66, /Math\.random\s*\(\).*token|token.*Math\.random\s*\(\)/i, "Math.random is predictable and unsuitable for security tokens.", "Use crypto.randomBytes, crypto.randomUUID, or Web Crypto.", "Add a test that token generation uses a cryptographic API."),
  rule("js-supabase-service-role-client", "Supabase service role key used in application code", "critical", "medium", 92, /(SUPABASE_SERVICE_ROLE_KEY|service_role)/i, "Supabase service role credentials bypass row-level security and must not be exposed to client or route code.", "Keep service role usage in isolated server-only modules and enforce row-level security for user paths.", "Add a test or build check that service role variables are not imported by client bundles.", false, {
    owasp: owaspCategory("LLM06:2025"),
    evidence: "Application code references a Supabase service role credential.",
    attackPath: "Code path uses service role key -> request or tool path bypasses row-level security.",
    impact: "This can grant excessive agency over database records and bypass tenant isolation."
  }),
  rule("js-express-route-no-obvious-auth", "Express route has no obvious auth middleware", "low", "low", 30, /app\.(get|post|put|patch|delete)\s*\([^,]+,\s*(async\s*)?\(?\s*(req|request)\s*,/i, "New routes may accidentally miss authorization checks.", "Add explicit authentication and authorization middleware or document why the route is public.", "Add route tests for unauthenticated and unauthorized requests.")
];

const PY_RULES: Rule[] = [
  rule("py-eval-exec", "Python eval or exec usage", "high", "high", 90, /\b(eval|exec)\s*\(/i, "Dynamic Python execution can run attacker-controlled input.", "Replace dynamic execution with explicit parsing or dispatch.", "Add a test proving untrusted input is rejected.", false, {
    evidence: "Python eval or exec executes dynamically supplied code.",
    attackPath: "Untrusted text reaches eval or exec -> Python interpreter executes it.",
    impact: "This can execute attacker-controlled code in the application process."
  }),
  rule("py-sql-string-format", "SQL query uses string formatting", "high", "high", 86, /f["'][^"']*(SELECT|INSERT|UPDATE|DELETE)[^"']*\{|["'][^"']*(SELECT|INSERT|UPDATE|DELETE)[^"']*%s?["']\s*%|\.format\s*\([^)]*\)/i, "String-formatted SQL can allow injection.", "Use parameterized queries for the database driver.", "Add a test with quotes and SQL metacharacters in user input.", false, {
    evidence: "A SQL statement is built with Python string formatting.",
    attackPath: "Attacker controls formatted value -> value changes SQL syntax -> database executes attacker-selected query logic.",
    impact: "This can expose, modify, or delete application data."
  }),
  rule("py-subprocess-shell-user-input", "subprocess shell=True with user input", "critical", "high", 96, /subprocess\.[^(]+\([^)]*(request\.|input\s*\(|sys\.argv|args)[^)]*shell\s*=\s*True|subprocess\.[^(]+\([^)]*shell\s*=\s*True[^)]*(request\.|input\s*\(|sys\.argv|args)/i, "Shell execution with user-controlled input can lead to command injection.", "Use shell=False with an argument list and allowlisted commands.", "Add a test that shell metacharacters are not interpreted.", false, {
    evidence: "subprocess is invoked with shell=True and user-controlled input.",
    attackPath: "Attacker controls command value -> shell=True interprets metacharacters.",
    impact: "This can execute arbitrary commands on the application host."
  }),
  rule("py-pickle-loads", "pickle.loads usage", "high", "medium", 78, /pickle\.loads?\s*\(/i, "Pickle can execute code during deserialization.", "Use JSON or a safe serialization format for untrusted data.", "Add a test that untrusted serialized input is rejected.", false, {
    evidence: "Pickle deserialization is used.",
    attackPath: "Attacker supplies pickle payload -> Python deserializer imports and executes payload behavior.",
    impact: "Untrusted pickle data can execute code during deserialization."
  }),
  rule("py-yaml-unsafe-load", "yaml.load without SafeLoader", "high", "high", 82, /yaml\.load\s*\((?![^)]*(SafeLoader|safe_load))/i, "Unsafe YAML loading can instantiate arbitrary objects.", "Use yaml.safe_load or specify SafeLoader.", "Add a test with a malicious YAML tag.", false, {
    evidence: "yaml.load is called without SafeLoader.",
    attackPath: "Attacker supplies YAML document -> unsafe loader constructs arbitrary objects.",
    impact: "Unsafe YAML loading can execute code or instantiate attacker-controlled objects."
  }),
  rule("py-requests-verify-false", "requests disables TLS verification", "high", "high", 88, /requests\.\w+\([^)]*verify\s*=\s*False/i, "Disabling TLS verification allows machine-in-the-middle attacks.", "Remove verify=False and configure trusted certificates explicitly.", "Add a test that HTTP clients verify certificates by default.", false, {
    evidence: "requests call disables certificate verification.",
    attackPath: "Application connects over HTTPS without certificate validation -> network attacker impersonates service.",
    impact: "This can expose prompts, model outputs, credentials, or application data in transit."
  }),
  rule("py-debug-true", "Debug mode enabled", "medium", "high", 65, /debug\s*=\s*True|DEBUG\s*=\s*True/i, "Debug mode can expose stack traces, secrets, and interactive consoles.", "Disable debug mode outside local development.", "Add a configuration test for production settings.", false, {
    evidence: "Debug mode is explicitly enabled.",
    attackPath: "Production request triggers error -> debug page exposes internals or console behavior.",
    impact: "Debug mode can disclose secrets, stack traces, and application internals."
  }),
  rule("py-weak-random-token", "random module used for token generation", "medium", "high", 66, /random\.\w+\([^)]*\).*token|token.*random\.\w+\(/i, "The random module is predictable and unsuitable for security tokens.", "Use secrets.token_urlsafe or os.urandom-backed APIs.", "Add a test that token generation uses the secrets module."),
  rule("py-jwt-no-verify", "JWT verification disabled", "high", "high", 84, /jwt\.decode\([^)]*(verify\s*=\s*False|verify_signature["']?\s*:\s*False|options\s*=\s*\{[^}]*verify_signature["']?\s*:\s*False)/i, "JWTs must be signature-verified before trusting claims.", "Enable verification and validate issuer, audience, algorithm, and expiry.", "Add a test that a tampered token is rejected.", false, {
    evidence: "JWT decoding disables signature verification.",
    attackPath: "Attacker supplies tampered token -> application trusts unverified claims.",
    impact: "This can bypass authentication or authorization decisions."
  }),
  rule("py-permissive-cors", "Permissive CORS", "medium", "medium", 60, /CORS\s*\([^)]*(origins\s*=\s*["']\*["']|resources\s*=\s*["']\*["'])/i, "Wildcard CORS can expose authenticated APIs to untrusted origins.", "Allowlist expected origins.", "Add a test for rejected untrusted origins."),
  rule("py-django-csrf-exempt", "Django CSRF protection disabled", "high", "high", 82, /@csrf_exempt\b/i, "Disabling CSRF protection on Django views can allow cross-site request forgery.", "Remove csrf_exempt or replace it with a narrowly scoped, authenticated non-browser endpoint.", "Add a test that browser-origin form submissions require a CSRF token."),
  rule("py-flask-route-no-obvious-auth", "Flask route has no obvious auth guard", "low", "low", 30, /@\w+\.route\s*\(/i, "New Flask routes may accidentally miss authentication or authorization checks.", "Add explicit authentication and authorization decorators or document why the route is public.", "Add route tests for unauthenticated and unauthorized requests.")
];

const FIREBASE_RULES: Rule[] = [
  rule("firebase-public-rules", "Firebase rules allow public access", "critical", "high", 94, /allow\s+(read|write|read\s*,\s*write)\s*:\s*if\s+true\s*;/i, "Public Firebase read or write rules can expose or mutate production data.", "Require authenticated users and resource-level authorization conditions.", "Add emulator tests proving unauthenticated reads and writes are denied.", false, {
    owasp: owaspCategory("LLM02:2025"),
    evidence: "Firebase security rules allow public reads or writes.",
    attackPath: "Unauthenticated caller reaches Firebase -> rule condition is true -> data can be read or modified.",
    impact: "Public rules can expose sensitive user data or allow unauthorized data changes."
  })
];

export function runCodeScanner(files: DiffFile[]): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    if (isTestFixtureFile(file.path)) continue;
    const rules = isJavaScriptFile(file.path)
      ? JS_RULES
      : isPythonFile(file.path)
        ? PY_RULES
        : isFirebaseRulesFile(file.path)
          ? FIREBASE_RULES
          : [];
    if (rules.length === 0) continue;

    for (const line of file.addedLines) {
      for (const ruleDefinition of rules) {
        const matchTarget = ruleDefinition.stripStrings ? stripStringsAndLineComment(line.content) : line.content;
        if (!ruleDefinition.pattern.test(matchTarget)) continue;
        if (ruleDefinition.unless?.test(line.content)) continue;
        if (ruleDefinition.requiresFilePattern && !ruleDefinition.requiresFilePattern.test(file.addedLines.map((candidate) => candidate.content).join("\n"))) continue;
        findings.push(scannerFinding({
          ruleId: ruleDefinition.id,
          title: ruleDefinition.title,
          severity: ruleDefinition.severity,
          confidence: ruleDefinition.confidence,
          riskScore: ruleDefinition.riskScore,
          file: file.path,
          line: line.line,
          snippet: maskSecretsInText(line.content),
          owasp: ruleDefinition.owasp,
          evidence: ruleDefinition.evidence ?? `Matched code: ${maskSecretsInText(line.content).trim()}`,
          attackPath: ruleDefinition.attackPath,
          impact: ruleDefinition.impact,
          why: ruleDefinition.why,
          suggestedFix: ruleDefinition.fix,
          testSuggestion: ruleDefinition.test
        }));
      }
    }
  }

  return findings;
}

function rule(
  id: string,
  title: string,
  severity: Rule["severity"],
  confidence: Rule["confidence"],
  riskScore: number,
  pattern: RegExp,
  why: string,
  fix: string,
  test: string,
  stripStrings = false,
  metadata: Pick<Rule, "owasp" | "evidence" | "attackPath" | "impact" | "unless" | "requiresFilePattern"> = {}
): Rule {
  return { id, title, severity, confidence, riskScore, pattern, stripStrings, why, fix, test, ...metadata };
}

function isTestFixtureFile(path: string): boolean {
  return /(^|\/)(__tests__|tests?|spec)\//.test(path) || /\.(test|spec)\.[cm]?[jt]sx?$/.test(path);
}

function isFirebaseRulesFile(path: string): boolean {
  return /(^|\/)(firestore|storage)\.rules$/.test(path);
}

function stripStringsAndLineComment(line: string): string {
  let output = "";
  let quote = "";
  let escaped = false;

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    const next = line[index + 1];

    if (!quote && char === "/" && next === "/") break;

    if (quote) {
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === quote) {
        quote = "";
      }
      output += " ";
      continue;
    }

    if (char === "\"" || char === "'" || char === "`") {
      quote = char;
      output += " ";
      continue;
    }

    output += char;
  }

  return output;
}
