import type { DiffFile, Finding } from "../../core/src/types.ts";
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
  why: string;
  fix: string;
  test: string;
};

const JS_RULES: Rule[] = [
  rule("js-eval", "JavaScript eval usage", "high", "high", 90, /\beval\s*\(/i, "Dynamic code execution can run attacker-controlled input.", "Replace eval with a safe parser, explicit mapping, or validated command dispatch.", "Add a test proving untrusted input is rejected instead of executed.", true),
  rule("js-function-constructor", "Function constructor usage", "high", "high", 88, /(^|[^\w.])(?:new\s+)?Function\s*\(/, "The Function constructor executes strings as code.", "Replace dynamic function construction with explicit functions or a constrained expression parser.", "Add a test for a malicious expression string.", true),
  rule("js-sql-template-interpolation", "SQL query uses template interpolation", "high", "high", 86, /`[^`]*\b(SELECT\b[^`]*\bFROM\b|INSERT\b[^`]*\bINTO\b|UPDATE\b[^`]*\bSET\b|DELETE\b[^`]*\bFROM\b)[^`]*\$\{/i, "Interpolating values into SQL can allow injection.", "Use parameterized queries or prepared statements.", "Add a test with quote characters in user input."),
  rule("js-child-process-exec-user-input", "child_process.exec with request-derived input", "critical", "high", 96, /\bexec\s*\([^)]*(req\.|request\.|ctx\.request|params|query|body|input)/i, "Shell execution with user-controlled input can lead to command injection.", "Use execFile or spawn with an argument array and strict allowlists.", "Add a test that shell metacharacters are treated as data."),
  rule("js-log-secret", "Secret or authorization value logged", "medium", "medium", 55, /console\.(log|warn|error|info)\([^)]*(authorization|password|secret|token|api[_-]?key)/i, "Logs often outlive requests and can expose credentials.", "Remove the secret from logs or log only non-sensitive metadata.", "Add a test or lint case ensuring sensitive headers are redacted."),
  rule("js-jwt-decode-no-verify", "JWT decoded without verification", "high", "high", 84, /\bjwt\.decode\s*\(|verify\s*:\s*false/i, "Decoded JWTs are not trusted unless their signature and claims are verified.", "Use JWT verification with expected issuer, audience, algorithm, and expiry checks.", "Add a test that a tampered token is rejected."),
  rule("js-permissive-cors", "Permissive CORS", "medium", "medium", 60, /cors\s*\([^)]*origin\s*:\s*["']\*["']|Access-Control-Allow-Origin["']?\s*,\s*["']\*["']/i, "Wildcard CORS can expose authenticated APIs to untrusted origins.", "Allowlist expected origins and avoid credentials with wildcard origins.", "Add a test for rejected untrusted origins."),
  rule("js-insecure-cookie", "Insecure cookie options", "high", "medium", 78, /(res\.cookie|cookie)\([^)]*(secure\s*:\s*false|httpOnly\s*:\s*false|sameSite\s*:\s*["']none["'])/i, "Missing secure cookie controls can expose session data.", "Set secure, httpOnly, and an appropriate SameSite policy for session cookies.", "Add a test that session cookies include secure attributes."),
  rule("js-tls-disabled", "TLS verification disabled", "high", "high", 88, /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|rejectUnauthorized\s*:\s*false/i, "Disabling TLS verification allows machine-in-the-middle attacks.", "Remove the override and configure trusted certificates explicitly.", "Add a test that HTTPS clients use certificate validation."),
  rule("js-ssrf-request-input", "Outbound request uses request-derived URL", "high", "medium", 76, /\b(fetch|axios(?:\.\w+)?)\s*\([^)]*(req\.|request\.|ctx\.request|params|query|body)/i, "Fetching request-controlled URLs can enable SSRF.", "Validate destination hosts against an allowlist and block internal networks.", "Add tests for blocked loopback and metadata-service URLs."),
  rule("js-path-traversal", "Filesystem access uses request-derived path", "high", "medium", 76, /\b(readFile|readFileSync|createReadStream|writeFile|writeFileSync|sendFile)\s*\([^)]*(req\.|request\.|params|query|body|\.\.)/i, "Request-controlled filesystem paths can allow path traversal.", "Resolve paths under an allowed base directory and reject traversal.", "Add tests for ../ traversal and absolute paths."),
  rule("js-weak-random-token", "Math.random used for token generation", "medium", "high", 66, /Math\.random\s*\(\).*token|token.*Math\.random\s*\(\)/i, "Math.random is predictable and unsuitable for security tokens.", "Use crypto.randomBytes, crypto.randomUUID, or Web Crypto.", "Add a test that token generation uses a cryptographic API."),
  rule("js-express-route-no-obvious-auth", "Express route has no obvious auth middleware", "low", "low", 30, /app\.(get|post|put|patch|delete)\s*\([^,]+,\s*(async\s*)?\(?\s*(req|request)\s*,/i, "New routes may accidentally miss authorization checks.", "Add explicit authentication and authorization middleware or document why the route is public.", "Add route tests for unauthenticated and unauthorized requests.")
];

const PY_RULES: Rule[] = [
  rule("py-eval-exec", "Python eval or exec usage", "high", "high", 90, /\b(eval|exec)\s*\(/i, "Dynamic Python execution can run attacker-controlled input.", "Replace dynamic execution with explicit parsing or dispatch.", "Add a test proving untrusted input is rejected."),
  rule("py-sql-string-format", "SQL query uses string formatting", "high", "high", 86, /f["'][^"']*(SELECT|INSERT|UPDATE|DELETE)[^"']*\{|["'][^"']*(SELECT|INSERT|UPDATE|DELETE)[^"']*%s?["']\s*%|\.format\s*\([^)]*\)/i, "String-formatted SQL can allow injection.", "Use parameterized queries for the database driver.", "Add a test with quotes and SQL metacharacters in user input."),
  rule("py-subprocess-shell-user-input", "subprocess shell=True with user input", "critical", "high", 96, /subprocess\.[^(]+\([^)]*(request\.|input\s*\(|sys\.argv|args)[^)]*shell\s*=\s*True|subprocess\.[^(]+\([^)]*shell\s*=\s*True[^)]*(request\.|input\s*\(|sys\.argv|args)/i, "Shell execution with user-controlled input can lead to command injection.", "Use shell=False with an argument list and allowlisted commands.", "Add a test that shell metacharacters are not interpreted."),
  rule("py-pickle-loads", "pickle.loads usage", "high", "medium", 78, /pickle\.loads?\s*\(/i, "Pickle can execute code during deserialization.", "Use JSON or a safe serialization format for untrusted data.", "Add a test that untrusted serialized input is rejected."),
  rule("py-yaml-unsafe-load", "yaml.load without SafeLoader", "high", "high", 82, /yaml\.load\s*\((?![^)]*(SafeLoader|safe_load))/i, "Unsafe YAML loading can instantiate arbitrary objects.", "Use yaml.safe_load or specify SafeLoader.", "Add a test with a malicious YAML tag."),
  rule("py-requests-verify-false", "requests disables TLS verification", "high", "high", 88, /requests\.\w+\([^)]*verify\s*=\s*False/i, "Disabling TLS verification allows machine-in-the-middle attacks.", "Remove verify=False and configure trusted certificates explicitly.", "Add a test that HTTP clients verify certificates by default."),
  rule("py-debug-true", "Debug mode enabled", "medium", "high", 65, /debug\s*=\s*True|DEBUG\s*=\s*True/i, "Debug mode can expose stack traces, secrets, and interactive consoles.", "Disable debug mode outside local development.", "Add a configuration test for production settings."),
  rule("py-weak-random-token", "random module used for token generation", "medium", "high", 66, /random\.\w+\([^)]*\).*token|token.*random\.\w+\(/i, "The random module is predictable and unsuitable for security tokens.", "Use secrets.token_urlsafe or os.urandom-backed APIs.", "Add a test that token generation uses the secrets module."),
  rule("py-jwt-no-verify", "JWT verification disabled", "high", "high", 84, /jwt\.decode\([^)]*(verify\s*=\s*False|verify_signature["']?\s*:\s*False|options\s*=\s*\{[^}]*verify_signature["']?\s*:\s*False)/i, "JWTs must be signature-verified before trusting claims.", "Enable verification and validate issuer, audience, algorithm, and expiry.", "Add a test that a tampered token is rejected."),
  rule("py-permissive-cors", "Permissive CORS", "medium", "medium", 60, /CORS\s*\([^)]*(origins\s*=\s*["']\*["']|resources\s*=\s*["']\*["'])/i, "Wildcard CORS can expose authenticated APIs to untrusted origins.", "Allowlist expected origins.", "Add a test for rejected untrusted origins.")
];

export function runCodeScanner(files: DiffFile[]): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    if (isTestFixtureFile(file.path)) continue;
    const rules = isJavaScriptFile(file.path) ? JS_RULES : isPythonFile(file.path) ? PY_RULES : [];
    if (rules.length === 0) continue;

    for (const line of file.addedLines) {
      for (const ruleDefinition of rules) {
        const matchTarget = ruleDefinition.stripStrings ? stripStringsAndLineComment(line.content) : line.content;
        if (!ruleDefinition.pattern.test(matchTarget)) continue;
        findings.push(scannerFinding({
          ruleId: ruleDefinition.id,
          title: ruleDefinition.title,
          severity: ruleDefinition.severity,
          confidence: ruleDefinition.confidence,
          riskScore: ruleDefinition.riskScore,
          file: file.path,
          line: line.line,
          snippet: maskSecretsInText(line.content),
          why: ruleDefinition.why,
          suggestedFix: ruleDefinition.fix,
          testSuggestion: ruleDefinition.test
        }));
      }
    }
  }

  return findings;
}

function rule(id: string, title: string, severity: Rule["severity"], confidence: Rule["confidence"], riskScore: number, pattern: RegExp, why: string, fix: string, test: string, stripStrings = false): Rule {
  return { id, title, severity, confidence, riskScore, pattern, stripStrings, why, fix, test };
}

function isTestFixtureFile(path: string): boolean {
  return /(^|\/)(__tests__|tests?|spec)\//.test(path) || /\.(test|spec)\.[cm]?[jt]sx?$/.test(path);
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
