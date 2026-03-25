# CLAUDE.md — SSPM-O365

## Project Overview

**Microsoft 365 SSPM Scanner** — a single-file Python tool that performs live SaaS Security Posture Management assessments against Microsoft 365 tenants via the Microsoft Graph API.

- **Repo**: `SSPM-O365`
- **Main file**: `o365_scanner.py` (v2.1.0, ~3,770 lines)
- **Language**: Python 3.9+
- **Dependency**: `requests` (sole external dependency)

## Architecture

Single-file scanner. No modules, no packages — intentionally kept as one self-contained script for easy deployment.

### Key components (in order of appearance in file):

1. **Constants** — `GRAPH_V1`, `GRAPH_BETA`, `TOKEN_URL`, `GRAPH_SCOPE`
2. **`PRIVILEGED_ROLE_IDS`** — Dict mapping Entra ID role template GUIDs to human names
3. **`HIGH_RISK_PERMISSION_IDS`** — Dict mapping dangerous OAuth permission GUIDs to names
4. **`COMPLIANCE_MAP`** — Dict mapping every `rule_id` to `{cis_m365, nist_800_53, iso_27001, soc2}` control IDs
5. **`Finding`** class — Data class for scan results. Auto-enriches with compliance data from `COMPLIANCE_MAP` on init
6. **`O365Scanner`** class — Main scanner with:
   - `scan()` — Entry point, calls all `_check_*()` methods
   - `_authenticate()` — OAuth 2.0 client credentials flow
   - `_graph_get()` / `_graph_get_single()` — Paginated Graph API helpers with error handling
   - `_check_*()` — 24 check group methods (each self-contained)
   - `print_report()` / `save_json()` / `save_html()` — Three output formats
7. **`main()`** — CLI entry point with `argparse`

### Check group numbering:

- 1-7: Entra ID (Security Defaults, CA, MFA, Privileged Access, Password, Apps, Guests)
- 8-12: M365 Services (Exchange, SharePoint, OneDrive, Teams, Audit)
- 13: Identity Protection
- 14-20: v2.0.0 additions (Secure Score, Intune, DLP, Defender, Sessions, Cross-Tenant, OAuth)
- 21-24: v2.1.0 additions (Auth Strengths, Governance, Named Locations, Stale Users)

## Conventions

### Rule IDs

Format: `M365-{CATEGORY}-{NNN}` where category is a short prefix:
- `SEC`, `CA`, `MFA`, `PRIV`, `PWD`, `APP`, `GUEST`, `EXO`, `SPO`, `OD`, `TEAMS`, `AUDIT`, `IDP`, `SCORE`, `INTUNE`, `DLP`, `MDO`, `SESSION`, `XTA`, `CONSENT`, `AUTH`, `GOV`, `LOC`, `STALE`

### Finding fields

- `file_path` — Repurposed as the Graph API endpoint being checked
- `line_num` — Always `None` (API scanner, not file scanner)
- `line_content` — Repurposed as the setting name and current value
- `cwe` — CWE ID for the weakness category
- `compliance` — Auto-populated dict from `COMPLIANCE_MAP`

### Adding a new check group

1. Add a `_check_new_group()` method in the scanner class
2. Call it from `scan()` in the appropriate section
3. Add compliance mappings to `COMPLIANCE_MAP` for every new rule ID
4. Update README check groups table
5. Add any new Graph API permissions to the docstring, CLI epilog, and README

### Adding a new rule to an existing group

1. Add the Finding call inside the existing `_check_*()` method
2. Add the rule ID to `COMPLIANCE_MAP`
3. Follow the existing naming: next sequential number in that category

### Compliance mapping

Every rule MUST have an entry in `COMPLIANCE_MAP`. The four frameworks are:
- `cis_m365` — CIS Microsoft 365 Foundations Benchmark v3.1.0 section number
- `nist_800_53` — NIST SP 800-53 Rev 5 control ID(s), comma-separated
- `iso_27001` — ISO/IEC 27001:2022 Annex A control
- `soc2` — SOC 2 Trust Services Criteria code(s)

## Development Guidelines

- **Single-file**: Do not split into modules. The single-file design is intentional for ease of deployment.
- **Read-only**: The scanner must NEVER modify the tenant. Only `GET` requests to Graph API.
- **Graceful degradation**: If a Graph API endpoint returns 403/404, log a verbose skip message and continue. Never crash on missing permissions.
- **No new dependencies**: Avoid adding new pip packages. The `requests`-only footprint is a feature.
- **HTML self-contained**: The HTML report must be a single file with no external CSS/JS dependencies.
- **Severity levels**: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` — use `CRITICAL` sparingly (active compromise indicators, total absence of fundamental controls).
- **"Verify:" findings**: Used when Graph API cannot directly check a setting (requires Exchange PowerShell, etc.). Include the PowerShell command in the description.

## Running

```bash
# Basic
python o365_scanner.py --tenant-id TENANT --client-id CLIENT --client-secret SECRET

# With reports
python o365_scanner.py -t TENANT -c CLIENT -s SECRET --json report.json --html report.html -v

# Syntax check only (no tenant needed)
python -m py_compile o365_scanner.py
```

## Testing

No test suite yet. Verify with:
- `python -m py_compile o365_scanner.py` — Syntax check
- `python o365_scanner.py --version` — Version prints correctly
- `python o365_scanner.py --help` — CLI help renders
