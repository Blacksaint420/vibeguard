# Local Dashboard

`vibeguard dashboard` generates a static, self-contained HTML dashboard from local VibeGuard artifacts. It is a review layer for developers, security teams, and GRC teams; it does not replace CLI or CI blocking controls.

## Generate From An Evidence Directory

```bash
vibeguard dashboard --input .vibeguard/evidence/latest --output .vibeguard/evidence/latest/dashboard.html
```

The input directory can contain:

```text
manifest.json
aibom.json
aibom-diff.json
sast.json
sast.sarif
risk.json
agent-graph.json
change-risk.json
suppressions.json
grc-mappings.json
```

Missing sections render as unavailable panels with the command needed to create the missing artifact.

## Generate From Individual Artifacts

```bash
vibeguard dashboard \
  --risk-json reports/risk.json \
  --aibom reports/aibom.json \
  --graph reports/agent-graph.json \
  --output reports/vibeguard-dashboard.html
```

Explicit artifact flags override files discovered from `--input`.

## CI Artifact Example

```yaml
- name: Generate VibeGuard dashboard
  run: |
    vibeguard check . --format json --output .vibeguard/evidence/latest/sast.json
    vibeguard aibom . --format aibom-json --output .vibeguard/evidence/latest/aibom.json
    vibeguard graph . --format graph-json --output .vibeguard/evidence/latest/agent-graph.json
    vibeguard dashboard --input .vibeguard/evidence/latest --output .vibeguard/evidence/latest/dashboard.html

- name: Upload VibeGuard dashboard
  uses: actions/upload-artifact@v4
  with:
    name: vibeguard-dashboard
    path: .vibeguard/evidence/latest/dashboard.html
```

The `upload-artifact` step is user-controlled CI behavior. VibeGuard itself does not upload dashboard content.

## Privacy

The dashboard command reads local JSON artifacts and writes one local HTML file. It does not upload source, prompts, AI BOMs, graphs, findings, suppressions, exceptions, secrets, or telemetry by default. The generated HTML may contain security evidence from supplied artifacts, so handle it as a security artifact.

## V1 Limits

- No hosted service, auth, multi-tenancy, billing, cloud storage, telemetry, or external upload flow.
- No external scripts, stylesheets, fonts, images, analytics, CDNs, or graph layout libraries.
- No source-file reconstruction for missing sections.
- Dashboard generation exits based on HTML generation success, not on findings inside artifacts.
