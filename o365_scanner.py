#!/usr/bin/env python3
"""
Microsoft 365 SSPM Scanner v2.0.0
SaaS Security Posture Management scanner for Microsoft 365 tenants.

Performs live Microsoft Graph API checks across:
  - Entra ID (Azure AD) — security defaults, conditional access, MFA,
    privileged access, identity protection, guest/external settings
  - Exchange Online — SMTP auth, audit logging, anti-phishing
  - SharePoint Online / OneDrive — external sharing settings
  - Microsoft Teams — external access, guest access, meeting security
  - M365 Compliance — unified audit log, DLP, retention
  - Microsoft Secure Score — score analysis, improvement actions
  - Intune / Endpoint Manager — device compliance, enrollment
  - Data Loss Prevention — DLP policies, sensitivity labels
  - Microsoft Defender for Office 365 — anti-phishing, safe links/attachments
  - Token & Session Policies — sign-in frequency, persistent browser
  - Cross-Tenant Access — B2B collaboration, trust settings
  - Admin Consent & OAuth Governance — consent workflow, risky apps

Authentication: OAuth 2.0 Client Credentials (app-only, no user required)
  1. Register an app in Entra ID (App Registrations)
  2. Grant the application permissions listed below
  3. Create a client secret
  4. Pass --tenant-id, --client-id, --client-secret

Required Microsoft Graph Application Permissions (read-only):
  Organization.Read.All              -- org settings, security defaults
  Policy.Read.All                    -- conditional access, auth methods policy
  Directory.Read.All                 -- directory roles, users, groups
  User.Read.All                      -- user sign-in activity, MFA state
  AuditLog.Read.All                  -- sign-in logs, audit events
  IdentityRiskyUser.Read.All         -- risky users, identity protection
  Application.Read.All               -- app registrations, service principals
  RoleManagement.Read.All            -- PIM, role assignments
  Reports.Read.All                   -- MFA registration report
  UserAuthenticationMethod.Read.All  -- per-user auth methods
  PrivilegedAccess.Read.AzureAD      -- PIM eligible assignments
  SharePointTenantSettings.Read.All  -- SharePoint external sharing
  SecurityEvents.Read.All            -- Secure Score
  DeviceManagementConfiguration.Read.All  -- Intune device compliance
  DeviceManagementManagedDevices.Read.All -- Intune managed devices
  InformationProtectionPolicy.Read.All    -- DLP, sensitivity labels
  CrossTenantInformation.ReadBasic.All    -- Cross-tenant access
  Policy.Read.ConditionalAccess      -- Token lifetime policies

Usage:
  python o365_scanner.py \\
      --tenant-id  <tenant-id-or-domain> \\
      --client-id  <app-client-id> \\
      --client-secret <secret>

Env var fallback:  M365_TENANT_ID  M365_CLIENT_ID  M365_CLIENT_SECRET
"""

import os
import re
import sys
import json
import html as html_mod
import argparse
from datetime import datetime, timezone, timedelta

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

VERSION = "2.0.0"

# ============================================================
# Microsoft Graph API constants
# ============================================================
GRAPH_V1   = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"
TOKEN_URL  = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

# Template IDs of privileged Entra ID directory roles
PRIVILEGED_ROLE_IDS = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "75941009-915a-4869-abe7-691bff18279e": "Skype for Business Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
}

# High-risk OAuth/Graph API permission IDs (GUIDs) — app-level delegated permissions
HIGH_RISK_PERMISSION_IDS = {
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
    "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
    "62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All",
    "dbaae8cf-10b5-4b86-a4a1-f871c94c6695": "GroupMember.ReadWrite.All",
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
    "246dd0d5-5bd0-4def-940b-0421030a5b68": "Policy.ReadWrite.ConditionalAccess",
    "be74164b-cff1-491c-8741-e671cb536e13": "AuditLog.Read.All",
    "a3410be2-8e48-4f32-8454-c29a7465209d": "Mail.ReadWrite",
    "e2a3a72e-5f79-4c64-b1b1-878b674786c9": "Mail.ReadWrite.Shared",
    "7ab1d382-f21e-4acd-a863-ba3e13f7da61": "Directory.Read.All",
    "741f803b-c850-494e-b5df-cde7c675a1ca": "User.ReadWrite.All",
    "4d02b0cc-d90b-441f-8d51-76ad77654f70": "MailboxSettings.ReadWrite",
    "ef54d2bf-783f-4e0f-bca1-3210c0444d99": "ConsentRequest.ReadWrite.All",
    "78145de6-330d-4a04-b0a0-3c72c765b44a": "Domain.ReadWrite.All",
    "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30": "Application.ReadWrite.OwnedBy",
}


# ============================================================
# Finding data class  (identical schema to all other scanners)
# ============================================================
class Finding:
    def __init__(self, rule_id, name, category, severity,
                 file_path, line_num, line_content,
                 description, recommendation, cwe=None, cve=None):
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.severity = severity
        self.file_path = file_path       # repurposed: Graph API endpoint / entity
        self.line_num = line_num         # always None for API checks
        self.line_content = line_content # repurposed: setting name = current value
        self.description = description
        self.recommendation = recommendation
        self.cwe = cwe or ""
        self.cve = cve or ""

    def to_dict(self):
        return {
            "id": self.rule_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "file": self.file_path,
            "line": self.line_num,
            "code": self.line_content,
            "description": self.description,
            "recommendation": self.recommendation,
            "cwe": self.cwe,
            "cve": self.cve,
        }


# ============================================================
# Microsoft 365 SSPM Scanner
# ============================================================
class O365Scanner:

    SEVERITY_ORDER = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
    SEVERITY_COLOR = {
        "CRITICAL": "\033[91m",
        "HIGH":     "\033[93m",
        "MEDIUM":   "\033[94m",
        "LOW":      "\033[92m",
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    def __init__(self, tenant_id: str, client_id: str,
                 client_secret: str, verbose: bool = False):
        self.tenant_id    = tenant_id
        self.client_id    = client_id
        self.client_secret = client_secret
        self.verbose      = verbose
        self.findings: list[Finding] = []
        self._token: str = ""
        self._token_expiry: datetime = datetime.now(timezone.utc)
        self._org_name: str = ""

    # ----------------------------------------------------------
    # Entry point
    # ----------------------------------------------------------
    def scan(self):
        print(f"[*] Microsoft 365 SSPM Scanner v{VERSION}")
        print("[*] Authenticating …")
        try:
            self._authenticate()
        except Exception as e:
            print(f"[!] Authentication failed: {e}", file=sys.stderr)
            sys.exit(1)
        print("[*] Running checks …\n")

        # ── Entra ID ──
        self._check_security_defaults()
        self._check_conditional_access()
        self._check_mfa_registration()
        self._check_privileged_access()
        self._check_password_policy()
        self._check_app_registrations()
        self._check_guest_and_external_access()
        self._check_identity_protection()

        # ── M365 Services ──
        self._check_exchange_security()
        self._check_sharepoint_security()
        self._check_onedrive_security()
        self._check_teams_security()
        self._check_audit_logging()

        # ── v2.0.0 New Checks ──
        self._check_secure_score()
        self._check_intune_compliance()
        self._check_dlp_and_labels()
        self._check_defender_for_o365()
        self._check_token_session_policies()
        self._check_cross_tenant_access()
        self._check_admin_consent_workflow()

    # ----------------------------------------------------------
    # OAuth 2.0 Authentication (Client Credentials)
    # ----------------------------------------------------------
    def _authenticate(self):
        """Obtain an access token using the OAuth 2.0 client credentials flow."""
        url = TOKEN_URL.format(tenant=self.tenant_id)
        resp = requests.post(url, data={
            "grant_type":    "client_credentials",
            "client_id":     self.client_id,
            "client_secret": self.client_secret,
            "scope":         GRAPH_SCOPE,
        }, timeout=30)
        if resp.status_code != 200:
            err = resp.json() if resp.headers.get("Content-Type", "").startswith("application/json") else {}
            raise RuntimeError(err.get("error_description") or resp.text[:300])
        body = resp.json()
        self._token = body["access_token"]
        expires_in = int(body.get("expires_in", 3600))
        self._token_expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in - 60)

        # Resolve tenant display name
        org = self._graph_get_single("organization")
        self._org_name = org.get("displayName", self.tenant_id) if org else self.tenant_id
        print(f"[*] Tenant  : {self._org_name} ({self.tenant_id})")

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept":        "application/json",
            "Content-Type":  "application/json",
        }

    # ----------------------------------------------------------
    # Microsoft Graph API helpers
    # ----------------------------------------------------------
    def _graph_get(self, endpoint: str, params: dict = None,
                   beta: bool = False) -> list[dict]:
        """
        Paginated GET from Microsoft Graph v1.0 (or beta).
        Returns list of items from 'value' array.
        Returns [] on error (with warning).
        """
        base = GRAPH_BETA if beta else GRAPH_V1
        url = f"{base}/{endpoint.lstrip('/')}"
        results = []
        first = True

        while url:
            try:
                resp = requests.get(
                    url,
                    headers=self._headers(),
                    params=params if first else None,
                    timeout=30,
                )
                first = False
            except requests.exceptions.ConnectionError as e:
                self._warn(f"Cannot reach Graph API: {e}")
                return []
            except requests.exceptions.Timeout:
                self._warn(f"Timeout fetching {endpoint}")
                return []

            if resp.status_code == 401:
                self._warn("Token expired or invalid.")
                return []
            if resp.status_code == 403:
                self._warn(
                    f"Permission denied for '{endpoint}'. "
                    "Ensure all required application permissions are granted and "
                    "admin consent has been provided."
                )
                return []
            if resp.status_code == 404:
                self._vprint(f"  [skip] '{endpoint}' not found (feature/license may not be active).")
                return []
            if resp.status_code != 200:
                self._warn(f"HTTP {resp.status_code} for '{endpoint}': {resp.text[:200]}")
                return []

            try:
                body = resp.json()
            except ValueError:
                self._warn(f"Non-JSON response from '{endpoint}'")
                return []

            value = body.get("value")
            if isinstance(value, list):
                results.extend(value)
            elif isinstance(body, dict) and "value" not in body:
                results.append(body)

            url = body.get("@odata.nextLink")

        self._vprint(f"  [api] {endpoint}: {len(results)} item(s)")
        return results

    def _graph_get_single(self, endpoint: str, params: dict = None,
                          beta: bool = False) -> dict:
        """Return the first (or only) record from a Graph endpoint, or {}."""
        results = self._graph_get(endpoint, params=params, beta=beta)
        return results[0] if results else {}

    # ----------------------------------------------------------
    # 1. Security Defaults
    # ----------------------------------------------------------
    def _check_security_defaults(self):
        self._vprint("  [check] Security defaults …")
        policy = self._graph_get_single("policies/identitySecurityDefaultsEnforcementPolicy")
        if not policy:
            return

        if not policy.get("isEnabled", False):
            ca_policies = self._graph_get("identity/conditionalAccessPolicies")
            enabled_ca = [p for p in ca_policies if p.get("state") == "enabled"]
            if not enabled_ca:
                self._add(Finding(
                    rule_id="M365-SEC-001",
                    name="Security Defaults disabled and no Conditional Access policies enforced",
                    category="Security Baseline",
                    severity="CRITICAL",
                    file_path="policies/identitySecurityDefaultsEnforcementPolicy",
                    line_num=None,
                    line_content="isEnabled = false, enforced CA policies = 0",
                    description=(
                        "Security Defaults are disabled and no Conditional Access policies are "
                        "in enforced mode. This means there are no platform-level controls "
                        "requiring MFA, blocking legacy authentication, or protecting privileged "
                        "accounts. Any credential compromise grants immediate, unrestricted access."
                    ),
                    recommendation=(
                        "Either re-enable Security Defaults (Admin Center > Azure AD > Properties > "
                        "Manage Security Defaults) OR create and enforce Conditional Access policies "
                        "that replicate the same protections: MFA for all users, block legacy auth, "
                        "protect privileged roles."
                    ),
                    cwe="CWE-1391",
                ))

        if policy.get("isEnabled", False):
            ca_policies = self._graph_get("identity/conditionalAccessPolicies")
            enabled_ca = [p for p in ca_policies if p.get("state") == "enabled"]
            if enabled_ca:
                self._add(Finding(
                    rule_id="M365-SEC-002",
                    name="Security Defaults enabled alongside active Conditional Access policies",
                    category="Security Baseline",
                    severity="MEDIUM",
                    file_path="policies/identitySecurityDefaultsEnforcementPolicy",
                    line_num=None,
                    line_content=f"isEnabled = true, enforced CA policies = {len(enabled_ca)}",
                    description=(
                        "Security Defaults and Conditional Access policies are both active. "
                        "This configuration can cause unexpected authentication failures because "
                        "Security Defaults apply fixed rules that may conflict with granular CA policies."
                    ),
                    recommendation=(
                        "Disable Security Defaults and rely exclusively on Conditional Access "
                        "policies for finer-grained control. Ensure CA policies cover all "
                        "protections that Security Defaults provided."
                    ),
                    cwe="CWE-1188",
                ))

    # ----------------------------------------------------------
    # 2. Conditional Access Policies
    # ----------------------------------------------------------
    def _check_conditional_access(self):
        self._vprint("  [check] Conditional Access policies …")
        policies = self._graph_get("identity/conditionalAccessPolicies")
        if not policies:
            self._add(Finding(
                rule_id="M365-CA-001",
                name="No Conditional Access policies found",
                category="Conditional Access",
                severity="CRITICAL",
                file_path="identity/conditionalAccessPolicies",
                line_num=None,
                line_content="CA policies = 0",
                description=(
                    "No Conditional Access policies exist in the tenant. Without CA policies, "
                    "there are no controls enforcing MFA, blocking legacy authentication, "
                    "restricting access by location/device, or protecting privileged accounts."
                ),
                recommendation=(
                    "Implement at minimum:\n"
                    "1. Require MFA for all users\n"
                    "2. Require MFA for all admins\n"
                    "3. Block legacy authentication\n"
                    "4. Block risky sign-ins\n"
                    "Use Microsoft's CA policy templates as a starting point."
                ),
                cwe="CWE-1391",
            ))
            return

        enabled  = [p for p in policies if p.get("state") == "enabled"]
        report   = [p for p in policies if p.get("state") == "enabledForReportingButNotEnforced"]
        disabled = [p for p in policies if p.get("state") == "disabled"]

        if report and not enabled:
            self._add(Finding(
                rule_id="M365-CA-002",
                name=f"All Conditional Access policies are in report-only mode ({len(report)} policies)",
                category="Conditional Access",
                severity="CRITICAL",
                file_path="identity/conditionalAccessPolicies",
                line_num=None,
                line_content=f"enforced = 0, report-only = {len(report)}, disabled = {len(disabled)}",
                description=(
                    "Every Conditional Access policy is in report-only (monitoring) mode. "
                    "No policies are actually enforced, meaning none of the access controls "
                    "(MFA, legacy auth blocking, device compliance) are applied to users."
                ),
                recommendation=(
                    "Transition report-only policies to 'On' (enforced) mode. "
                    "Review the sign-in log impact before enabling to avoid disruption. "
                    "Start with admin-only policies, then broaden scope."
                ),
                cwe="CWE-1391",
            ))
            return

        if report:
            names = ", ".join(p.get("displayName", "?") for p in report[:5])
            self._add(Finding(
                rule_id="M365-CA-003",
                name=f"{len(report)} Conditional Access policy/policies still in report-only mode",
                category="Conditional Access",
                severity="MEDIUM",
                file_path="identity/conditionalAccessPolicies",
                line_num=None,
                line_content=f"Report-only: {names}",
                description=(
                    f"{len(report)} CA policy/policies are in report-only mode and not enforced. "
                    "These represent intended security controls that have not yet been activated."
                ),
                recommendation=(
                    "Review the sign-in impact report for each report-only policy and enable "
                    "those that are ready. Prioritise policies blocking legacy auth and "
                    "requiring admin MFA."
                ),
                cwe="CWE-1391",
            ))

        has_mfa_all_users = False
        has_mfa_admins    = False
        has_block_legacy  = False
        has_risky_signins = False
        has_device_compliance = False
        has_location_policy = False

        for p in enabled:
            conditions   = p.get("conditions", {})
            grant        = p.get("grantControls") or {}
            users_cond   = conditions.get("users", {})
            include_users = users_cond.get("includeUsers", [])
            include_roles = users_cond.get("includeRoles", [])
            client_apps  = conditions.get("clientAppTypes", [])
            sign_in_risk = conditions.get("signInRiskLevels", [])
            locations    = conditions.get("locations", {})
            built_in     = grant.get("builtInControls", [])

            if ("All" in include_users) and "mfa" in built_in:
                has_mfa_all_users = True

            admin_roles_targeted = bool(set(include_roles) & set(PRIVILEGED_ROLE_IDS.keys()))
            if admin_roles_targeted and "mfa" in built_in:
                has_mfa_admins = True

            legacy_clients = {"exchangeActiveSync", "other"}
            if set(client_apps) & legacy_clients and "block" in built_in:
                has_block_legacy = True

            if sign_in_risk and "block" in built_in:
                has_risky_signins = True

            if "compliantDevice" in built_in or "domainJoinedDevice" in built_in:
                has_device_compliance = True

            if locations.get("includeLocations") or locations.get("excludeLocations"):
                has_location_policy = True

        if not has_mfa_all_users:
            self._add(Finding(
                rule_id="M365-CA-004",
                name="No enforced Conditional Access policy requires MFA for all users",
                category="Conditional Access",
                severity="CRITICAL",
                file_path="identity/conditionalAccessPolicies",
                line_num=None,
                line_content="MFA for All Users CA policy = not found (enforced)",
                description=(
                    "No active (enforced) CA policy requires MFA for all users. "
                    "Any account with a stolen or phished password can be immediately "
                    "used to access M365 email, OneDrive, Teams, and connected applications "
                    "without a second factor."
                ),
                recommendation=(
                    "Create a CA policy: Users = All Users, Grant = Require MFA, State = Enabled. "
                    "Exclude break-glass emergency accounts and service accounts from scope. "
                    "Test in report-only mode before enabling."
                ),
                cwe="CWE-308",
            ))

        if not has_mfa_admins:
            self._add(Finding(
                rule_id="M365-CA-005",
                name="No enforced Conditional Access policy requires MFA for administrators",
                category="Conditional Access",
                severity="CRITICAL",
                file_path="identity/conditionalAccessPolicies",
                line_num=None,
                line_content="MFA for Admins CA policy = not found (enforced)",
                description=(
                    "No active CA policy specifically enforces MFA for privileged admin roles. "
                    "Admin accounts are high-value targets — a compromised admin account "
                    "can modify security policies, disable MFA for other users, grant "
                    "new admin rights, and exfiltrate the entire organisation's data."
                ),
                recommendation=(
                    "Create a CA policy targeting all privileged directory roles "
                    "(Global Admin, Security Admin, etc.) requiring MFA. "
                    "Also require a compliant or hybrid-joined device for admin access."
                ),
                cwe="CWE-308",
            ))

        if not has_block_legacy:
            self._add(Finding(
                rule_id="M365-CA-006",
                name="No enforced Conditional Access policy blocks legacy authentication",
                category="Conditional Access",
                severity="HIGH",
                file_path="identity/conditionalAccessPolicies",
                line_num=None,
                line_content="Block Legacy Auth CA policy = not found (enforced)",
                description=(
                    "Legacy authentication protocols (IMAP, POP3, SMTP AUTH, "
                    "Exchange ActiveSync with Basic Auth, older Office clients) do not "
                    "support MFA. Attackers use these protocols to bypass MFA entirely "
                    "during credential-stuffing attacks. Over 99% of password spray "
                    "attacks use legacy authentication."
                ),
                recommendation=(
                    "Create a CA policy: Client apps = Exchange ActiveSync + Other legacy, "
                    "Grant = Block. Exclude service accounts that legitimately use SMTP. "
                    "First audit which users rely on legacy auth via the sign-in logs."
                ),
                cwe="CWE-308",
            ))

        if not has_risky_signins:
            self._add(Finding(
                rule_id="M365-CA-007",
                name="No enforced Conditional Access policy responds to risky sign-ins",
                category="Conditional Access",
                severity="HIGH",
                file_path="identity/conditionalAccessPolicies",
                line_num=None,
                line_content="Sign-in risk CA policy = not found (enforced)",
                description=(
                    "No CA policy blocks or challenges sign-ins flagged as medium/high risk "
                    "by Entra ID Protection (e.g., impossible travel, anonymous proxy, "
                    "leaked credentials). Without this, Entra ID detects risky sign-ins "
                    "but takes no automated action."
                ),
                recommendation=(
                    "Create a CA policy: Sign-in risk = High and Medium, Grant = Require MFA "
                    "or Block. Requires Entra ID P2 licence. "
                    "Also create a User Risk policy blocking high-risk users."
                ),
                cwe="CWE-287",
            ))

        if not has_device_compliance:
            self._add(Finding(
                rule_id="M365-CA-008",
                name="No Conditional Access policy requires compliant or managed device",
                category="Conditional Access",
                severity="MEDIUM",
                file_path="identity/conditionalAccessPolicies",
                line_num=None,
                line_content="Device compliance CA policy = not found (enforced)",
                description=(
                    "No CA policy requires a device to be Intune-compliant or "
                    "hybrid-joined before accessing M365 resources. Without this, users "
                    "can access corporate data from unmanaged, potentially compromised "
                    "personal devices with no endpoint controls."
                ),
                recommendation=(
                    "Create CA policies requiring compliant device for access to sensitive "
                    "apps (Exchange, SharePoint, Teams). Enrol devices in Microsoft Intune "
                    "and define compliance policies covering OS version, encryption, and AV."
                ),
                cwe="CWE-284",
            ))

        if not has_location_policy:
            self._add(Finding(
                rule_id="M365-CA-009",
                name="No Conditional Access policy uses location-based conditions",
                category="Conditional Access",
                severity="LOW",
                file_path="identity/conditionalAccessPolicies",
                line_num=None,
                line_content="Location-based CA policy = not found (enforced)",
                description=(
                    "No active CA policy restricts access based on named locations "
                    "(trusted IPs, country allowlists). Without location-based conditions, "
                    "sign-ins from any country or IP are treated equally, limiting the "
                    "ability to detect or block access from unexpected geographies."
                ),
                recommendation=(
                    "Define named locations for trusted corporate IPs and allowed countries. "
                    "Create a CA policy that requires MFA or blocks access from untrusted "
                    "locations. Use impossible travel detection with sign-in risk policies."
                ),
                cwe="CWE-284",
            ))

    # ----------------------------------------------------------
    # 3. MFA Registration
    # ----------------------------------------------------------
    def _check_mfa_registration(self):
        self._vprint("  [check] MFA registration …")

        reg_details = self._graph_get(
            "reports/authenticationMethods/userRegistrationDetails",
            params={"$top": 999},
        )
        if not reg_details:
            self._vprint("  [skip] MFA registration report not accessible (Reports.Read.All required).")
            return

        total = len(reg_details)
        if total == 0:
            return

        no_mfa = [
            u for u in reg_details
            if not u.get("isMfaRegistered", False)
            and u.get("isEnabled", True)
        ]
        if no_mfa:
            pct = len(no_mfa) * 100 // total
            sample = ", ".join(u.get("userPrincipalName", "?") for u in no_mfa[:5])
            suffix = f" (+{len(no_mfa)-5} more)" if len(no_mfa) > 5 else ""
            self._add(Finding(
                rule_id="M365-MFA-001",
                name=f"{len(no_mfa)} active users ({pct}%) have no MFA method registered",
                category="Multi-Factor Authentication",
                severity="HIGH",
                file_path="reports/authenticationMethods/userRegistrationDetails",
                line_num=None,
                line_content=f"Users without MFA: {sample}{suffix}",
                description=(
                    f"{len(no_mfa)} of {total} active users ({pct}%) have no MFA method "
                    "registered. If a CA policy requires MFA, these users will be locked out. "
                    "If no CA policy requires MFA, these accounts are vulnerable to "
                    "credential-based attacks."
                ),
                recommendation=(
                    "Run an MFA registration campaign. Use the Combined Security Information "
                    "Registration portal (aka.ms/mfasetup). Block sign-in for users who "
                    "refuse to register after a deadline. Consider requiring registration "
                    "via a CA policy with a grace period."
                ),
                cwe="CWE-308",
            ))

        admin_no_mfa = [
            u for u in no_mfa
            if u.get("isAdmin", False)
        ]
        if admin_no_mfa:
            sample = ", ".join(u.get("userPrincipalName", "?") for u in admin_no_mfa[:5])
            self._add(Finding(
                rule_id="M365-MFA-002",
                name=f"Admin users without MFA registered ({len(admin_no_mfa)})",
                category="Multi-Factor Authentication",
                severity="CRITICAL",
                file_path="reports/authenticationMethods/userRegistrationDetails",
                line_num=None,
                line_content=f"Admins without MFA: {sample}",
                description=(
                    f"{len(admin_no_mfa)} administrator account(s) have no MFA method registered. "
                    "An admin account compromised without MFA gives an attacker full control "
                    "over the M365 tenant: all mailboxes, all SharePoint data, all Teams, "
                    "and the ability to create new admin accounts or modify CA policies."
                ),
                recommendation=(
                    "Immediately enforce MFA registration for all admin accounts. "
                    "Block admin sign-in until MFA is registered. "
                    "Use FIDO2 security keys or Microsoft Authenticator (not SMS) for admin MFA."
                ),
                cwe="CWE-308",
            ))

        sms_only = [
            u for u in reg_details
            if u.get("isMfaRegistered", False)
            and u.get("isEnabled", True)
            and set(u.get("methodsRegistered", [])) <= {"mobilePhone", "alternateMobilePhone"}
        ]
        if sms_only:
            pct_sms = len(sms_only) * 100 // total
            self._add(Finding(
                rule_id="M365-MFA-003",
                name=f"{len(sms_only)} users ({pct_sms}%) rely only on SMS/voice call for MFA",
                category="Multi-Factor Authentication",
                severity="MEDIUM",
                file_path="reports/authenticationMethods/userRegistrationDetails",
                line_num=None,
                line_content=f"SMS-only MFA users = {len(sms_only)} ({pct_sms}%)",
                description=(
                    "SMS and voice call MFA methods are vulnerable to SIM-swapping attacks, "
                    "SS7 network interception, and social engineering of mobile carriers. "
                    "NIST SP 800-63B no longer recommends SMS OTP as a primary authenticator."
                ),
                recommendation=(
                    "Migrate users to Microsoft Authenticator (TOTP or Push), FIDO2 "
                    "security keys, or certificate-based authentication. "
                    "Admin accounts must use phishing-resistant MFA (FIDO2 or CBA)."
                ),
                cwe="CWE-308",
            ))

        sspr_no_mfa = [
            u for u in reg_details
            if u.get("isSsprRegistered", False)
            and not u.get("isMfaRegistered", False)
            and u.get("isEnabled", True)
        ]
        if sspr_no_mfa:
            self._add(Finding(
                rule_id="M365-MFA-004",
                name=f"{len(sspr_no_mfa)} users registered for SSPR but not MFA",
                category="Multi-Factor Authentication",
                severity="MEDIUM",
                file_path="reports/authenticationMethods/userRegistrationDetails",
                line_num=None,
                line_content=f"SSPR-only users = {len(sspr_no_mfa)}",
                description=(
                    "Users registered for Self-Service Password Reset (SSPR) but not MFA "
                    "can reset their own passwords using SSPR authentication methods that "
                    "may be weaker than MFA requirements. In some configurations, SSPR "
                    "can be used to bypass MFA challenges."
                ),
                recommendation=(
                    "Enable combined registration so SSPR and MFA share authentication methods. "
                    "Ensure SSPR requires at least 2 verification methods including "
                    "one strong factor (Authenticator app, FIDO2)."
                ),
                cwe="CWE-640",
            ))

    # ----------------------------------------------------------
    # 4. Privileged Access
    # ----------------------------------------------------------
    def _check_privileged_access(self):
        self._vprint("  [check] Privileged access …")

        roles = self._graph_get("directoryRoles")
        if not roles:
            return

        all_priv_members: list[dict] = []

        for role in roles:
            role_template_id = role.get("roleTemplateId", "")
            role_name = PRIVILEGED_ROLE_IDS.get(role_template_id, "")
            if not role_name:
                continue

            members = self._graph_get(f"directoryRoles/{role['id']}/members")
            for m in members:
                m["_role_name"] = role_name
                m["_role_template_id"] = role_template_id
            all_priv_members.extend(members)

        global_admins = [
            m for m in all_priv_members
            if m.get("_role_template_id") == "62e90394-69f5-4237-9190-012177145e10"
        ]
        if len(global_admins) > 5:
            sample = ", ".join(
                m.get("userPrincipalName") or m.get("displayName", "?")
                for m in global_admins[:5]
            )
            self._add(Finding(
                rule_id="M365-PRIV-001",
                name=f"Too many Global Administrators ({len(global_admins)})",
                category="Privileged Access",
                severity="HIGH",
                file_path="directoryRoles/members",
                line_num=None,
                line_content=f"Global Admins: {sample} (+{len(global_admins)-5} more)" if len(global_admins) > 5 else f"Global Admins: {sample}",
                description=(
                    f"{len(global_admins)} Global Administrators are assigned. "
                    "Global Admin is the most privileged role in M365 — it can modify any "
                    "setting, access any mailbox, and grant itself any other permission. "
                    "Each additional Global Admin is an additional attack surface."
                ),
                recommendation=(
                    "Reduce Global Admins to 2-4 named break-glass accounts. "
                    "Replace day-to-day admin tasks with least-privilege roles: "
                    "Exchange Admin, User Admin, Security Admin, etc. "
                    "Use PIM to provide just-in-time Global Admin elevation."
                ),
                cwe="CWE-269",
            ))

        guest_admins = [
            m for m in all_priv_members
            if m.get("userType") == "Guest" or
               (m.get("userPrincipalName", "") and "#EXT#" in m.get("userPrincipalName", ""))
        ]
        if guest_admins:
            sample = ", ".join(
                m.get("userPrincipalName") or m.get("displayName", "?")
                for m in guest_admins[:5]
            )
            self._add(Finding(
                rule_id="M365-PRIV-002",
                name=f"Guest user(s) assigned privileged directory roles ({len(guest_admins)})",
                category="Privileged Access",
                severity="CRITICAL",
                file_path="directoryRoles/members",
                line_num=None,
                line_content=f"Guest admins: {sample}",
                description=(
                    f"{len(guest_admins)} guest (external) user(s) hold privileged directory "
                    "roles. Guest accounts are managed outside your organisation's lifecycle "
                    "processes and may persist after contractor/vendor relationships end. "
                    "A compromised guest account with admin rights can cause a full tenant breach."
                ),
                recommendation=(
                    "Remove privileged roles from all guest accounts immediately. "
                    "If external admins are needed, require them to be onboarded as "
                    "regular users (not guests) with full identity governance controls."
                ),
                cwe="CWE-269",
            ))

        sp_admins = [
            m for m in global_admins
            if m.get("@odata.type") == "#microsoft.graph.servicePrincipal"
        ]
        if sp_admins:
            sample = ", ".join(m.get("displayName", "?") for m in sp_admins[:5])
            self._add(Finding(
                rule_id="M365-PRIV-003",
                name=f"Service principals with Global Administrator role ({len(sp_admins)})",
                category="Privileged Access",
                severity="CRITICAL",
                file_path="directoryRoles/members",
                line_num=None,
                line_content=f"Service principal Global Admins: {sample}",
                description=(
                    "Service principals (non-human identities such as apps, automation tools) "
                    "should never hold the Global Administrator role. A compromised app "
                    "credential (client secret or certificate) with Global Admin rights "
                    "provides unrestricted access to the entire tenant without user interaction."
                ),
                recommendation=(
                    "Remove Global Admin from all service principals. "
                    "Replace with the minimum required Microsoft Graph application permissions. "
                    "Review the app's permission model and use managed identities where possible."
                ),
                cwe="CWE-269",
            ))

        pim_schedules = self._graph_get(
            "roleManagement/directory/roleAssignmentSchedules",
            params={"$filter": "assignmentType eq 'Assigned'"},
        )
        permanent_privs = [
            s for s in pim_schedules
            if s.get("roleDefinitionId") in PRIVILEGED_ROLE_IDS
            and not s.get("scheduleInfo", {}).get("expiration", {}).get("endDateTime")
        ]
        if permanent_privs:
            role_counts: dict[str, int] = {}
            for s in permanent_privs:
                rn = PRIVILEGED_ROLE_IDS.get(s.get("roleDefinitionId", ""), "Unknown")
                role_counts[rn] = role_counts.get(rn, 0) + 1
            summary_str = ", ".join(f"{k}={v}" for k, v in sorted(role_counts.items()))
            self._add(Finding(
                rule_id="M365-PRIV-004",
                name=f"Permanent privileged role assignments without PIM expiry ({len(permanent_privs)})",
                category="Privileged Access",
                severity="HIGH",
                file_path="roleManagement/directory/roleAssignmentSchedules",
                line_num=None,
                line_content=f"Permanent assignments: {summary_str}",
                description=(
                    f"{len(permanent_privs)} privileged role assignments are permanent "
                    "(no expiry date configured). Permanent admin access violates the "
                    "principle of just-in-time access — admins should only hold "
                    "privileged roles when actively performing admin tasks."
                ),
                recommendation=(
                    "Convert permanent assignments to PIM eligible assignments. "
                    "Require justification, approval, and MFA for PIM activation. "
                    "Set a maximum activation duration of 8 hours. "
                    "Retain only 2-4 Global Admin permanent accounts for break-glass scenarios."
                ),
                cwe="CWE-269",
            ))

        if global_admins:
            breakglass_names = re.compile(
                r"(emergency|break.?glass|breakglass|bg.?admin|admin.?break)",
                re.IGNORECASE,
            )
            bg_accounts = [
                m for m in global_admins
                if breakglass_names.search(m.get("displayName", "") or m.get("userPrincipalName", ""))
            ]
            if not bg_accounts:
                self._add(Finding(
                    rule_id="M365-PRIV-005",
                    name="No identifiable emergency (break-glass) Global Admin accounts found",
                    category="Privileged Access",
                    severity="MEDIUM",
                    file_path="directoryRoles/members",
                    line_num=None,
                    line_content="Break-glass accounts: none detected by name pattern",
                    description=(
                        "No emergency access (break-glass) accounts with Global Admin role were "
                        "identified. Break-glass accounts are permanently assigned cloud-only "
                        "Global Admin accounts used when normal admin access is disrupted "
                        "(e.g., IdP outage, MFA failure, locked-out admin)."
                    ),
                    recommendation=(
                        "Create 2 cloud-only (not federated) Global Admin break-glass accounts. "
                        "Exclude them from all CA policies. Store credentials in a physical safe. "
                        "Monitor sign-ins via alerts — any sign-in should trigger an immediate "
                        "security review. See Microsoft's guidance: aka.ms/breakglass."
                    ),
                    cwe="CWE-1188",
                ))

    # ----------------------------------------------------------
    # 5. Password Policy
    # ----------------------------------------------------------
    def _check_password_policy(self):
        self._vprint("  [check] Password policy …")

        domains = self._graph_get("domains", params={
            "$select": "id,isDefault,passwordValidityPeriodInDays,passwordNotificationWindowInDays",
        })
        if not domains:
            return

        default_domain = next((d for d in domains if d.get("isDefault")), domains[0])
        pw_validity = default_domain.get("passwordValidityPeriodInDays", 90)

        if int(pw_validity) == 2147483647:
            sd_policy = self._graph_get_single("policies/identitySecurityDefaultsEnforcementPolicy")
            ca_policies = self._graph_get("identity/conditionalAccessPolicies")
            mfa_ca = [
                p for p in ca_policies
                if p.get("state") == "enabled"
                and "mfa" in (p.get("grantControls") or {}).get("builtInControls", [])
                and "All" in (p.get("conditions", {}).get("users", {}).get("includeUsers", []))
            ]
            if not mfa_ca and not sd_policy.get("isEnabled", False):
                self._add(Finding(
                    rule_id="M365-PWD-001",
                    name="Passwords set to never expire and MFA is not enforced",
                    category="Password Policy",
                    severity="HIGH",
                    file_path=f"domains/{default_domain['id']}",
                    line_num=None,
                    line_content="passwordValidityPeriodInDays = 2147483647 (never), MFA enforced = false",
                    description=(
                        "Passwords are configured to never expire AND no MFA policy enforces "
                        "a second factor for all users. While NIST recommends never-expire "
                        "passwords when MFA is present, without MFA this is a high-risk "
                        "configuration: compromised credentials remain valid indefinitely."
                    ),
                    recommendation=(
                        "Either enforce MFA for all users (preferred) or set a reasonable "
                        "password expiry (90 days). If MFA is enforced, never-expire passwords "
                        "are acceptable per NIST SP 800-63B."
                    ),
                    cwe="CWE-521",
                ))
        elif int(pw_validity) > 90:
            self._add(Finding(
                rule_id="M365-PWD-002",
                name=f"Password expiry period too long ({pw_validity} days)",
                category="Password Policy",
                severity="LOW",
                file_path=f"domains/{default_domain['id']}",
                line_num=None,
                line_content=f"passwordValidityPeriodInDays = {pw_validity}",
                description=(
                    f"Passwords expire every {pw_validity} days. Expiry periods longer than "
                    "90 days extend the window for compromised credentials to remain valid."
                ),
                recommendation=(
                    "Set password expiry to 90 days OR enable MFA for all users and "
                    "set passwords to never expire (NIST SP 800-63B)."
                ),
                cwe="CWE-521",
            ))

        auth_methods_policy = self._graph_get_single("policies/authenticationMethodsPolicy")
        if auth_methods_policy:
            registration_campaign = auth_methods_policy.get("registrationEnforcement", {})
            if not registration_campaign.get("authenticationMethodsRegistrationCampaign", {}).get("state", "") == "enabled":
                self._add(Finding(
                    rule_id="M365-PWD-003",
                    name="MFA registration campaign is not enabled",
                    category="Password Policy",
                    severity="LOW",
                    file_path="policies/authenticationMethodsPolicy",
                    line_num=None,
                    line_content="registrationEnforcement.state = not enabled",
                    description=(
                        "The Authentication Methods Registration Campaign is not enabled. "
                        "Without it, users are not automatically prompted to register MFA "
                        "methods when they sign in, making MFA adoption passive and slow."
                    ),
                    recommendation=(
                        "Enable the Registration Campaign in Entra ID > Authentication Methods > "
                        "Registration Campaign. Configure a snoozeable but time-limited prompt "
                        "to nudge users to register."
                    ),
                    cwe="CWE-308",
                ))

    # ----------------------------------------------------------
    # 6. Application Registrations
    # ----------------------------------------------------------
    def _check_app_registrations(self):
        self._vprint("  [check] App registrations …")

        apps = self._graph_get("applications", params={
            "$select": "id,displayName,passwordCredentials,keyCredentials,requiredResourceAccess,appRoles",
            "$top": 999,
        })
        if not apps:
            return

        now = datetime.now(timezone.utc)
        soon = now + timedelta(days=30)
        expired_secrets: list[str] = []
        expiring_soon: list[str] = []
        secret_only_apps: list[str] = []

        for app in apps:
            name = app.get("displayName", "?")
            pw_creds   = app.get("passwordCredentials", []) or []
            key_creds  = app.get("keyCredentials", []) or []

            for cred in pw_creds:
                end_str = cred.get("endDateTime", "")
                if end_str:
                    try:
                        end_dt = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
                        if end_dt < now:
                            expired_secrets.append(f"{name} (expired {end_dt.date()})")
                        elif end_dt < soon:
                            expiring_soon.append(f"{name} (expires {end_dt.date()})")
                    except ValueError:
                        pass

            if pw_creds and not key_creds:
                secret_only_apps.append(name)

            for res in (app.get("requiredResourceAccess") or []):
                for perm in (res.get("resourceAccess") or []):
                    perm_id = perm.get("id", "")
                    if perm_id in HIGH_RISK_PERMISSION_IDS:
                        perm_name = HIGH_RISK_PERMISSION_IDS[perm_id]
                        self._add(Finding(
                            rule_id="M365-APP-001",
                            name=f"App '{name}' has high-risk permission: {perm_name}",
                            category="Application Security",
                            severity="HIGH",
                            file_path=f"applications/{app['id']}",
                            line_num=None,
                            line_content=f"app = {name}, permission = {perm_name}",
                            description=(
                                f"Application '{name}' requests the high-risk permission "
                                f"'{perm_name}'. If this application or its credentials are "
                                "compromised, the attacker can perform actions that may "
                                "affect the entire tenant's security posture."
                            ),
                            recommendation=(
                                f"Review whether '{name}' genuinely requires '{perm_name}'. "
                                "Replace with a less-privileged permission if possible. "
                                "Ensure admin consent was reviewed and documented. "
                                "Monitor this application's activity via the sign-in audit log."
                            ),
                            cwe="CWE-269",
                        ))

        if expired_secrets:
            self._add(Finding(
                rule_id="M365-APP-002",
                name=f"App registrations with expired client secrets ({len(expired_secrets)})",
                category="Application Security",
                severity="HIGH",
                file_path="applications",
                line_num=None,
                line_content="; ".join(expired_secrets[:5]),
                description=(
                    f"{len(expired_secrets)} app registration(s) have expired client secrets. "
                    "Applications using expired secrets will fail to authenticate. "
                    "Expired secrets may also still be distributed to integration systems "
                    "that attempt to use them, generating noise and potential security alerts."
                ),
                recommendation=(
                    "Rotate expired secrets immediately. Implement a secret rotation process "
                    "with alerts 30 days before expiry. Consider using certificate credentials "
                    "instead of secrets, and Managed Identities for Azure-hosted workloads."
                ),
                cwe="CWE-324",
            ))

        if expiring_soon:
            self._add(Finding(
                rule_id="M365-APP-003",
                name=f"App registrations with secrets expiring within 30 days ({len(expiring_soon)})",
                category="Application Security",
                severity="MEDIUM",
                file_path="applications",
                line_num=None,
                line_content="; ".join(expiring_soon[:5]),
                description=(
                    f"{len(expiring_soon)} app registration secret(s) expire within 30 days. "
                    "If not rotated, dependent integrations will break when they expire."
                ),
                recommendation=(
                    "Rotate the listed secrets before their expiry dates. "
                    "Automate secret rotation using Azure Key Vault with auto-rotation policies."
                ),
                cwe="CWE-324",
            ))

        if secret_only_apps:
            self._add(Finding(
                rule_id="M365-APP-004",
                name=f"App registrations using client secrets instead of certificates ({len(secret_only_apps)})",
                category="Application Security",
                severity="MEDIUM",
                file_path="applications",
                line_num=None,
                line_content=f"Secret-only apps: {', '.join(secret_only_apps[:5])}",
                description=(
                    f"{len(secret_only_apps)} app(s) authenticate using client secrets (passwords) "
                    "rather than certificates. Client secrets are static strings that can be "
                    "accidentally logged, committed to source code, or leaked in configuration files. "
                    "Certificates are significantly harder to extract and can be hardware-protected."
                ),
                recommendation=(
                    "Migrate app authentication to certificate credentials (X.509). "
                    "For Azure-hosted services, use Managed Identities to eliminate credentials entirely. "
                    "Store certificates in Azure Key Vault and automate renewal."
                ),
                cwe="CWE-321",
            ))

        if len(apps) > 100:
            self._add(Finding(
                rule_id="M365-APP-005",
                name=f"High number of app registrations ({len(apps)}) — sprawl risk",
                category="Application Security",
                severity="LOW",
                file_path="applications",
                line_num=None,
                line_content=f"total app registrations = {len(apps)}",
                description=(
                    f"{len(apps)} app registrations exist in the tenant. App sprawl makes it "
                    "difficult to audit permissions, detect stale or abandoned apps, and "
                    "respond quickly to a compromised application."
                ),
                recommendation=(
                    "Audit app registrations: remove those with no recent sign-in activity. "
                    "Implement an app governance policy requiring business justification, "
                    "owner assignment, and annual review for all app registrations."
                ),
                cwe="CWE-284",
            ))

    # ----------------------------------------------------------
    # 7. Guest and External Access
    # ----------------------------------------------------------
    def _check_guest_and_external_access(self):
        self._vprint("  [check] Guest and external access …")

        auth_policy = self._graph_get_single("policies/authorizationPolicy")
        if not auth_policy:
            return

        allow_invites = auth_policy.get("allowInvitesFrom", "adminsAndGuestInviters")
        if allow_invites in ("everyone", "allUsersWithMicrosoftAccounts"):
            self._add(Finding(
                rule_id="M365-GUEST-001",
                name=f"Guest invitations allowed by anyone (allowInvitesFrom = '{allow_invites}')",
                category="Guest Access",
                severity="HIGH",
                file_path="policies/authorizationPolicy",
                line_num=None,
                line_content=f"allowInvitesFrom = {allow_invites!r}",
                description=(
                    "Any user (or anyone with a Microsoft account) can invite external guests "
                    "to the tenant. This can lead to unauthorised guest accounts being created "
                    "without IT oversight, bypassing access reviews and data governance policies."
                ),
                recommendation=(
                    "Set allowInvitesFrom to 'adminsAndGuestInviters' or 'adminsGuestInvitersAndAllMemberUsers'. "
                    "Create a formal guest onboarding process with manager approval. "
                    "Restrict guest invites to specific approved domains via cross-tenant access settings."
                ),
                cwe="CWE-284",
            ))

        if auth_policy.get("allowedToInviteOthers", True):
            self._add(Finding(
                rule_id="M365-GUEST-002",
                name="Guest users can invite additional guests",
                category="Guest Access",
                severity="MEDIUM",
                file_path="policies/authorizationPolicy",
                line_num=None,
                line_content="allowedToInviteOthers = true (guest users can invite others)",
                description=(
                    "Guest users can invite additional external users to the tenant. "
                    "This allows a single external guest account to expand guest access "
                    "exponentially without requiring admin or even employee approval."
                ),
                recommendation=(
                    "Disable guest-to-guest invitations in Entra ID > External Identities > "
                    "External Collaboration Settings. Set 'Guest users can invite' to No."
                ),
                cwe="CWE-284",
            ))

        if auth_policy.get("allowEmailVerifiedUsersToJoinOrganization", False):
            self._add(Finding(
                rule_id="M365-GUEST-003",
                name="Email-verified users can join the organisation without an invitation",
                category="Guest Access",
                severity="HIGH",
                file_path="policies/authorizationPolicy",
                line_num=None,
                line_content="allowEmailVerifiedUsersToJoinOrganization = true",
                description=(
                    "Email-verified users (users who verify a Microsoft account via email) "
                    "can join the organisation without an explicit admin invitation. "
                    "This can allow unintended access to shared resources and self-service "
                    "resource discovery by external parties."
                ),
                recommendation=(
                    "Set allowEmailVerifiedUsersToJoinOrganization to false. "
                    "Require formal invitations for all guest access."
                ),
                cwe="CWE-284",
            ))

        guest_users = self._graph_get("users", params={
            "$filter": "userType eq 'Guest' and accountEnabled eq true",
            "$select": "id,displayName,userPrincipalName,createdDateTime",
            "$top": 999,
        })
        if guest_users:
            one_year_ago = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
            old_guests = [
                g for g in guest_users
                if g.get("createdDateTime", "") < one_year_ago
            ]
            if old_guests:
                self._add(Finding(
                    rule_id="M365-GUEST-004",
                    name=f"Long-standing guest accounts older than 1 year ({len(old_guests)})",
                    category="Guest Access",
                    severity="MEDIUM",
                    file_path="users",
                    line_num=None,
                    line_content=f"Guest accounts >1 year old = {len(old_guests)} of {len(guest_users)} total",
                    description=(
                        f"{len(old_guests)} guest accounts have existed for over a year. "
                        "Long-standing guest accounts may belong to ex-contractors, expired "
                        "vendor relationships, or former partners. They represent persistent "
                        "access that is often overlooked in quarterly access reviews."
                    ),
                    recommendation=(
                        "Implement automatic guest access reviews using Entra ID Access Reviews. "
                        "Configure guest account expiry (e.g., 365 days) in External Collaboration settings. "
                        "Remove guests who no longer need access."
                    ),
                    cwe="CWE-613",
                ))

    # ----------------------------------------------------------
    # 8. Exchange Online Security
    # ----------------------------------------------------------
    def _check_exchange_security(self):
        self._vprint("  [check] Exchange Online security …")

        org = self._graph_get_single("organization", params={
            "$select": "id,displayName,onPremisesSyncEnabled,technicalNotificationMails,securityComplianceNotificationMails",
        })
        if org:
            tech_notifs = org.get("technicalNotificationMails", []) or []
            sec_notifs  = org.get("securityComplianceNotificationMails", []) or []
            if not tech_notifs and not sec_notifs:
                self._add(Finding(
                    rule_id="M365-EXO-001",
                    name="No security or technical notification email addresses configured",
                    category="Exchange: Notifications",
                    severity="MEDIUM",
                    file_path="organization",
                    line_num=None,
                    line_content="technicalNotificationMails = [], securityComplianceNotificationMails = []",
                    description=(
                        "No notification email addresses are configured for technical or security "
                        "alerts. Microsoft sends service health alerts, security bulletins, and "
                        "breach notifications to these addresses. Without them, critical alerts "
                        "may be missed."
                    ),
                    recommendation=(
                        "Configure at least one technical and one security notification email "
                        "in M365 Admin Center > Settings > Org Settings > Organisation Profile. "
                        "Use a distribution group mailbox monitored by your security team."
                    ),
                    cwe="CWE-778",
                ))

        self._add(Finding(
            rule_id="M365-EXO-002",
            name="Verify: Automatic external email forwarding policy",
            category="Exchange: Email Forwarding",
            severity="HIGH",
            file_path="admin/exchangeSettings",
            line_num=None,
            line_content="AutoForwardEnabled — manual verification required via Exchange Admin",
            description=(
                "Automatic external email forwarding (via Outlook rules or transport rules) "
                "is a common data exfiltration technique. Attackers who compromise a mailbox "
                "configure silent forwarding rules to collect all email. "
                "This check requires Exchange Online PowerShell: "
                "Get-RemoteDomain | Select DomainName,AutoForwardEnabled"
            ),
            recommendation=(
                "Disable automatic external forwarding for all remote domains: "
                "Set-RemoteDomain Default -AutoForwardEnabled $false. "
                "In Exchange Admin Center > Mail flow > Remote domains, set AutoForwardEnabled = false. "
                "Enable anti-spam outbound policy to block forwarding: "
                "Set-HostedOutboundSpamFilterPolicy -AutoForwardingMode Off."
            ),
            cwe="CWE-200",
        ))

        legacy_signins = self._graph_get(
            "auditLogs/signIns",
            params={
                "$filter": "clientAppUsed eq 'IMAP4' or clientAppUsed eq 'POP3' or clientAppUsed eq 'SMTP'",
                "$top": 10,
                "$select": "id,clientAppUsed,userDisplayName,createdDateTime,status",
            },
        )
        if legacy_signins:
            apps_used = {s.get("clientAppUsed", "?") for s in legacy_signins}
            users_using = {s.get("userDisplayName", "?") for s in legacy_signins}
            self._add(Finding(
                rule_id="M365-EXO-003",
                name="Legacy email protocols (IMAP/POP3/SMTP) detected in recent sign-ins",
                category="Exchange: Legacy Authentication",
                severity="HIGH",
                file_path="auditLogs/signIns",
                line_num=None,
                line_content=f"Protocols: {', '.join(apps_used)} — Users: {', '.join(list(users_using)[:3])}",
                description=(
                    "Recent sign-in logs show IMAP, POP3, or SMTP authentication attempts. "
                    "These legacy protocols transmit credentials without supporting MFA, "
                    "allowing attackers to bypass Conditional Access policies that require MFA."
                ),
                recommendation=(
                    "Block IMAP/POP3/SMTP Basic Auth via a CA policy (Client apps = "
                    "Exchange ActiveSync + Other, Grant = Block). "
                    "Migrate affected email clients to modern OAuth-based authentication. "
                    "Disable per-user IMAP/POP3 in Exchange: Set-CASMailbox -Identity * "
                    "-ImapEnabled $false -PopEnabled $false."
                ),
                cwe="CWE-523",
            ))

        self._add(Finding(
            rule_id="M365-EXO-004",
            name="Verify: SMTP AUTH is disabled for mailboxes that don't need it",
            category="Exchange: SMTP Authentication",
            severity="MEDIUM",
            file_path="admin/exchangeSettings",
            line_num=None,
            line_content="SMTPClientAuthenticationDisabled — manual verification required",
            description=(
                "SMTP AUTH (Basic authentication over SMTP) allows email clients to send "
                "mail without MFA. It is commonly abused for spam and phishing campaigns "
                "after account compromise. Unless required for legacy applications, "
                "SMTP AUTH should be disabled organisation-wide. "
                "PowerShell check: Get-TransportConfig | Select SmtpClientAuthenticationDisabled"
            ),
            recommendation=(
                "Disable SMTP AUTH globally: Set-TransportConfig -SmtpClientAuthenticationDisabled $true. "
                "Re-enable only for specific mailboxes that require it: "
                "Set-CASMailbox -Identity <user> -SmtpClientAuthenticationDisabled $false. "
                "Use OAuth 2.0 SMTP for legitimate applications."
            ),
            cwe="CWE-523",
        ))

    # ----------------------------------------------------------
    # 9. SharePoint Online Security
    # ----------------------------------------------------------
    def _check_sharepoint_security(self):
        self._vprint("  [check] SharePoint Online …")

        sp_settings = self._graph_get_single("admin/sharepoint/settings")
        if not sp_settings:
            self._vprint("  [skip] SharePoint settings not accessible (SharePointTenantSettings.Read.All required).")
            return

        sharing_cap = sp_settings.get("sharingCapability", "")
        if sharing_cap in ("externalUserAndGuestSharing", "externalUserSharingOnly"):
            sev = "CRITICAL" if sharing_cap == "externalUserAndGuestSharing" else "HIGH"
            label = {
                "externalUserAndGuestSharing": "Anyone (anonymous links allowed)",
                "externalUserSharingOnly": "New and existing external users",
            }.get(sharing_cap, sharing_cap)
            self._add(Finding(
                rule_id="M365-SPO-001",
                name=f"SharePoint external sharing is set to: {label}",
                category="SharePoint: External Sharing",
                severity=sev,
                file_path="admin/sharepoint/settings",
                line_num=None,
                line_content=f"sharingCapability = {sharing_cap!r}",
                description=(
                    f"SharePoint external sharing is configured to allow '{label}'. "
                    "This allows users to share documents and sites with anyone outside "
                    "the organisation, including via anonymous links that require no authentication. "
                    "This is a common vector for data leakage."
                ),
                recommendation=(
                    "Set sharingCapability to 'existingExternalUserSharingOnly' (existing guests only) "
                    "or 'disabled' (internal only). If external sharing is required, restrict it "
                    "to specific domains via allowedDomainGuidsForSyncApp settings. "
                    "Enable anonymous link expiry and require MFA for link access."
                ),
                cwe="CWE-284",
            ))

        anon_expiry = sp_settings.get("anonymousLinkExpirationInDays", 0)
        if sharing_cap != "disabled" and int(anon_expiry or 0) == 0:
            self._add(Finding(
                rule_id="M365-SPO-002",
                name="Anonymous/Anyone sharing links have no expiration date",
                category="SharePoint: External Sharing",
                severity="HIGH",
                file_path="admin/sharepoint/settings",
                line_num=None,
                line_content="anonymousLinkExpirationInDays = 0 (no expiry)",
                description=(
                    "Sharing links that don't require sign-in (Anyone links) have no "
                    "expiration date. Once created, these links remain valid indefinitely, "
                    "allowing access even after the sharing intent has expired (e.g., after "
                    "a project ends or a contractor leaves)."
                ),
                recommendation=(
                    "Set anonymousLinkExpirationInDays to 14-30 days in SharePoint Admin Center "
                    "> Sharing > Advanced settings. Consider also requiring that recipients "
                    "must sign in via 'Specific people' links instead of Anyone links."
                ),
                cwe="CWE-284",
            ))

        default_link = sp_settings.get("defaultSharingLinkType", "")
        if default_link == "anonymous":
            self._add(Finding(
                rule_id="M365-SPO-003",
                name="Default SharePoint sharing link type is 'Anyone' (anonymous)",
                category="SharePoint: External Sharing",
                severity="HIGH",
                file_path="admin/sharepoint/settings",
                line_num=None,
                line_content="defaultSharingLinkType = anonymous",
                description=(
                    "When users share files in SharePoint or OneDrive, the default link "
                    "created is an anonymous 'Anyone' link. Users who click Share without "
                    "modifying the default settings will inadvertently create unauthenticated "
                    "links to corporate data."
                ),
                recommendation=(
                    "Change defaultSharingLinkType to 'organization' (company-wide) or "
                    "'specificPeople' in SharePoint Admin Center > Sharing. "
                    "Educate users on appropriate sharing practices."
                ),
                cwe="CWE-284",
            ))

        if sp_settings.get("isLegacyAuthProtocolsEnabled", False):
            self._add(Finding(
                rule_id="M365-SPO-004",
                name="Legacy authentication protocols enabled for SharePoint",
                category="SharePoint: Authentication",
                severity="HIGH",
                file_path="admin/sharepoint/settings",
                line_num=None,
                line_content="isLegacyAuthProtocolsEnabled = true",
                description=(
                    "Legacy authentication protocols (SharePoint Designer 2013, pre-2016 "
                    "Office clients) are enabled for SharePoint. These protocols do not "
                    "support MFA and can bypass Conditional Access policies."
                ),
                recommendation=(
                    "Disable legacy auth: Set isLegacyAuthProtocolsEnabled = false in "
                    "SharePoint Admin Center. Migrate clients to modern authentication."
                ),
                cwe="CWE-308",
            ))

    # ----------------------------------------------------------
    # 10. OneDrive Security  (NEW in v2.0.0)
    # ----------------------------------------------------------
    def _check_onedrive_security(self):
        self._vprint("  [check] OneDrive for Business …")

        sp_settings = self._graph_get_single("admin/sharepoint/settings")
        if not sp_settings:
            return

        # M365-OD-001: OneDrive sync restricted to managed devices
        if not sp_settings.get("isUnmanagedSyncAppForTenantRestricted", False):
            self._add(Finding(
                rule_id="M365-OD-001",
                name="OneDrive sync client is not restricted to managed/domain-joined devices",
                category="OneDrive: Sync Security",
                severity="HIGH",
                file_path="admin/sharepoint/settings",
                line_num=None,
                line_content="isUnmanagedSyncAppForTenantRestricted = false",
                description=(
                    "The OneDrive sync client can synchronize files to any device, including "
                    "unmanaged personal computers. This allows users to download and store "
                    "corporate data on devices outside the organisation's control, increasing "
                    "the risk of data leakage if the personal device is compromised or lost."
                ),
                recommendation=(
                    "Restrict OneDrive sync to domain-joined or Intune-compliant devices: "
                    "SharePoint Admin Center > Settings > Sync > 'Allow syncing only on PCs "
                    "joined to specific domains'. Add your AD domain GUIDs. "
                    "Also enforce device compliance via Conditional Access."
                ),
                cwe="CWE-284",
            ))

        # M365-OD-002: Personal site sharing capability
        od_sharing = sp_settings.get("oneDriveSharingCapability", "")
        if od_sharing in ("externalUserAndGuestSharing",):
            self._add(Finding(
                rule_id="M365-OD-002",
                name="OneDrive personal sites allow anonymous 'Anyone' sharing links",
                category="OneDrive: External Sharing",
                severity="HIGH",
                file_path="admin/sharepoint/settings",
                line_num=None,
                line_content=f"oneDriveSharingCapability = {od_sharing!r}",
                description=(
                    "OneDrive personal sites are configured to allow 'Anyone' sharing links. "
                    "Users can create unauthenticated links to their OneDrive files, which "
                    "may contain sensitive corporate data, personal notes about projects, "
                    "or copies of confidential documents."
                ),
                recommendation=(
                    "Set OneDrive sharing to 'Existing external users' or 'Only people in "
                    "your organisation'. OneDrive sharing should be equal to or more "
                    "restrictive than the SharePoint organisation-level sharing setting."
                ),
                cwe="CWE-284",
            ))

        # M365-OD-003: File storage retention for departed users
        od_retention = sp_settings.get("orphanedPersonalSitesRetentionPeriod", 0)
        if int(od_retention or 0) < 30:
            self._add(Finding(
                rule_id="M365-OD-003",
                name=f"OneDrive retention for deleted users is too short ({od_retention} days)",
                category="OneDrive: Data Retention",
                severity="MEDIUM",
                file_path="admin/sharepoint/settings",
                line_num=None,
                line_content=f"orphanedPersonalSitesRetentionPeriod = {od_retention}",
                description=(
                    f"When a user account is deleted, their OneDrive data is retained for "
                    f"only {od_retention} days. If legal hold, compliance, or manager review "
                    "is required, this may not provide sufficient time to preserve data."
                ),
                recommendation=(
                    "Set OneDrive retention to at least 365 days in SharePoint Admin Center > "
                    "Settings > OneDrive > Retention. Configure manager access delegation "
                    "so departed users' files are accessible to their manager."
                ),
                cwe="CWE-404",
            ))

    # ----------------------------------------------------------
    # 11. Microsoft Teams Security
    # ----------------------------------------------------------
    def _check_teams_security(self):
        self._vprint("  [check] Microsoft Teams …")

        teams_config = self._graph_get_single("teamwork/configuration", beta=True)
        if not teams_config:
            self._vprint("  [skip] Teams configuration not accessible via beta API.")
            return

        guest_settings = teams_config.get("guestSettings", {})
        federation     = teams_config.get("federationSettings", {})
        meeting        = teams_config.get("meetingSettings", {}) or {}

        allow_anon = meeting.get("allowAnonymousUsersToJoinMeeting", True)
        if allow_anon:
            self._add(Finding(
                rule_id="M365-TEAMS-001",
                name="Anonymous users can join Microsoft Teams meetings",
                category="Teams: Meeting Security",
                severity="MEDIUM",
                file_path="teamwork/configuration",
                line_num=None,
                line_content="allowAnonymousUsersToJoinMeeting = true",
                description=(
                    "Anonymous (unauthenticated) users can join Teams meetings without signing in. "
                    "This enables uninvited individuals to join meetings if they obtain the meeting "
                    "link, exposing confidential discussions and shared content to outsiders."
                ),
                recommendation=(
                    "Disable anonymous join in Teams Admin Center > Meetings > Meeting Policies. "
                    "Require participants to sign in with a Microsoft or partner account. "
                    "Enable meeting lobby for external participants."
                ),
                cwe="CWE-284",
            ))

        allow_all_external = federation.get("allowedUsersAndGroups", {}).get("isFederationEnabled", True)
        allowed_domains = federation.get("allowedDomains", []) or []
        if allow_all_external and not allowed_domains:
            self._add(Finding(
                rule_id="M365-TEAMS-002",
                name="Teams external access (federation) is open to all external domains",
                category="Teams: External Access",
                severity="MEDIUM",
                file_path="teamwork/configuration",
                line_num=None,
                line_content="federationSettings.allowedDomains = [] (all domains)",
                description=(
                    "Teams is configured to allow communication with all external "
                    "Microsoft Teams and Skype for Business organisations. Users can "
                    "receive messages from any external tenant, increasing the attack "
                    "surface for phishing and social engineering via Teams chat."
                ),
                recommendation=(
                    "Restrict external access to specific trusted partner domains in "
                    "Teams Admin Center > Users > External access. "
                    "Block all external domains by default and allowlist only those "
                    "you have a business relationship with."
                ),
                cwe="CWE-284",
            ))

        guest_enabled = guest_settings.get("allowGuestUser", True)
        if guest_enabled:
            self._add(Finding(
                rule_id="M365-TEAMS-003",
                name="Guest access to Microsoft Teams is enabled",
                category="Teams: Guest Access",
                severity="LOW",
                file_path="teamwork/configuration",
                line_num=None,
                line_content="guestSettings.allowGuestUser = true",
                description=(
                    "External guests can be added to Teams and access team channels, files, "
                    "and chat. While this is often a legitimate business requirement, guest "
                    "access should be reviewed to ensure guests cannot access sensitive teams "
                    "and that guest accounts are reviewed regularly."
                ),
                recommendation=(
                    "Review which Teams channels grant guest access. Enable the 'External "
                    "Collaboration' access reviews in Entra ID for Teams guest users. "
                    "Use sensitivity labels on Teams to prevent guests joining confidential teams."
                ),
                cwe="CWE-284",
            ))

    # ----------------------------------------------------------
    # 12. Audit Logging
    # ----------------------------------------------------------
    def _check_audit_logging(self):
        self._vprint("  [check] Unified audit logging …")

        self._add(Finding(
            rule_id="M365-AUDIT-001",
            name="Verify: Unified Audit Log is enabled in Microsoft Purview",
            category="Audit Logging",
            severity="HIGH",
            file_path="security/auditLog",
            line_num=None,
            line_content="Unified Audit Log status — verification required via Compliance portal",
            description=(
                "The Unified Audit Log (UAL) captures events across Exchange Online, "
                "SharePoint, OneDrive, Teams, Entra ID, and other M365 services. "
                "If UAL is disabled, there is no central record of user activity, "
                "admin changes, or data access — critical for incident response and compliance. "
                "PowerShell check: Get-AdminAuditLogConfig | Select UnifiedAuditLogIngestionEnabled"
            ),
            recommendation=(
                "Verify UAL is enabled: Purview portal > Audit > or "
                "Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true via PowerShell. "
                "E3/E5 licences include 90-day retention. Use E5 Compliance or Purview Audit "
                "Premium for 1-year retention. Export to Microsoft Sentinel for longer retention."
            ),
            cwe="CWE-778",
        ))

        self._add(Finding(
            rule_id="M365-AUDIT-002",
            name="Verify: Sign-in and audit logs are exported to long-term storage",
            category="Audit Logging",
            severity="MEDIUM",
            file_path="auditLogs/signIns",
            line_num=None,
            line_content="Log retention: Entra ID P1 = 30 days, Free = 7 days only",
            description=(
                "Entra ID sign-in logs and audit logs are retained for only 30 days (P1/P2) "
                "or 7 days (free tier). Security incidents are often discovered weeks or "
                "months after they occur. Without long-term log storage, forensic "
                "investigations are impossible."
            ),
            recommendation=(
                "Configure Diagnostic Settings in Entra ID to forward logs to: "
                "1. Microsoft Sentinel (recommended for SIEM/SOAR capabilities), "
                "2. Azure Log Analytics Workspace, or "
                "3. Azure Storage Account for long-term cold storage. "
                "Retain at least 90 days in hot storage and 365+ days in cold storage."
            ),
            cwe="CWE-778",
        ))

        self._add(Finding(
            rule_id="M365-AUDIT-003",
            name="Verify: Mailbox auditing is enabled for all mailboxes",
            category="Audit Logging",
            severity="MEDIUM",
            file_path="admin/exchangeSettings",
            line_num=None,
            line_content="AuditEnabled (per mailbox) — verify via Exchange PowerShell",
            description=(
                "Mailbox-level auditing records who accessed mailbox content, when, and "
                "from where — critical for detecting business email compromise (BEC). "
                "While mailbox audit logging is now on by default for E3/E5, it may be "
                "disabled on older mailboxes or through migration. "
                "PowerShell check: Get-Mailbox -ResultSize Unlimited | Where {$_.AuditEnabled -eq $false}"
            ),
            recommendation=(
                "Enable mailbox auditing globally: "
                "Set-OrganizationConfig -AuditDisabled $false. "
                "Verify per-mailbox: Get-Mailbox | Select Name,AuditEnabled. "
                "Ensure MailboxLogin, FolderBind, and SendAs operations are audited."
            ),
            cwe="CWE-778",
        ))

    # ----------------------------------------------------------
    # 13. Identity Protection
    # ----------------------------------------------------------
    def _check_identity_protection(self):
        self._vprint("  [check] Identity protection and risky users …")

        risky_users = self._graph_get(
            "identityProtection/riskyUsers",
            params={
                "$filter": "riskState eq 'atRisk' and riskLevel ne 'none'",
                "$select": "id,userDisplayName,userPrincipalName,riskLevel,riskDetail,riskLastUpdatedDateTime",
                "$top": 500,
            },
        )
        if risky_users:
            high_risk   = [u for u in risky_users if u.get("riskLevel") == "high"]
            medium_risk = [u for u in risky_users if u.get("riskLevel") == "medium"]

            if high_risk:
                sample = ", ".join(u.get("userPrincipalName", "?") for u in high_risk[:5])
                self._add(Finding(
                    rule_id="M365-IDP-001",
                    name=f"High-risk users not remediated ({len(high_risk)})",
                    category="Identity Protection",
                    severity="CRITICAL",
                    file_path="identityProtection/riskyUsers",
                    line_num=None,
                    line_content=f"High-risk users: {sample}",
                    description=(
                        f"{len(high_risk)} user account(s) are flagged as HIGH risk by "
                        "Entra ID Identity Protection. High-risk signals include: confirmed "
                        "credential leak, verified attacker sign-ins, or impossible travel from "
                        "atypical locations. These accounts may already be under attacker control."
                    ),
                    recommendation=(
                        "Immediately remediate high-risk users: block sign-in, require "
                        "password reset with MFA, and investigate sign-in history. "
                        "Use Investigate > Risky Users in the Entra ID portal. "
                        "Create a CA User Risk policy to automatically block high-risk users."
                    ),
                    cwe="CWE-287",
                ))

            if medium_risk:
                self._add(Finding(
                    rule_id="M365-IDP-002",
                    name=f"Medium-risk users not remediated ({len(medium_risk)})",
                    category="Identity Protection",
                    severity="HIGH",
                    file_path="identityProtection/riskyUsers",
                    line_num=None,
                    line_content=f"Medium-risk users = {len(medium_risk)}",
                    description=(
                        f"{len(medium_risk)} user account(s) are at medium risk. "
                        "Medium-risk signals include unfamiliar sign-in properties, anonymous "
                        "IP address usage, or malware-linked IP addresses. These accounts "
                        "require investigation and may need password reset."
                    ),
                    recommendation=(
                        "Require password reset + MFA challenge for medium-risk users. "
                        "Create a CA User Risk policy for medium risk that requires MFA and "
                        "password change. Investigate the specific risk detections for each user."
                    ),
                    cwe="CWE-287",
                ))

        id_protection_policy = self._graph_get_single("policies/identityProtection", beta=True)
        if id_protection_policy:
            sign_in_policy = id_protection_policy.get("signInRiskPolicy", {}) or {}
            user_risk_policy = id_protection_policy.get("userRiskPolicy", {}) or {}

            if sign_in_policy.get("state") != "enabled":
                self._add(Finding(
                    rule_id="M365-IDP-003",
                    name="Identity Protection sign-in risk policy is not enabled",
                    category="Identity Protection",
                    severity="HIGH",
                    file_path="policies/identityProtection",
                    line_num=None,
                    line_content=f"signInRiskPolicy.state = {sign_in_policy.get('state', 'not configured')!r}",
                    description=(
                        "The Entra ID Identity Protection sign-in risk policy is not enabled. "
                        "Without it, sign-ins flagged as medium/high risk (anonymous IP, "
                        "impossible travel, malware-linked) are not automatically challenged "
                        "or blocked — Entra ID detects the risk but takes no action."
                    ),
                    recommendation=(
                        "Enable the sign-in risk policy in Entra ID > Security > "
                        "Identity Protection > Sign-in risk policy. "
                        "Set risk level = Medium and above, Access = Require MFA. "
                        "Alternatively, configure an equivalent CA policy with Sign-in risk conditions."
                    ),
                    cwe="CWE-287",
                ))

            if user_risk_policy.get("state") != "enabled":
                self._add(Finding(
                    rule_id="M365-IDP-004",
                    name="Identity Protection user risk policy is not enabled",
                    category="Identity Protection",
                    severity="HIGH",
                    file_path="policies/identityProtection",
                    line_num=None,
                    line_content=f"userRiskPolicy.state = {user_risk_policy.get('state', 'not configured')!r}",
                    description=(
                        "The Entra ID Identity Protection user risk policy is not enabled. "
                        "Without it, users flagged at high risk (leaked credentials, confirmed "
                        "compromise) are not automatically required to reset their password — "
                        "the attacker can continue using the account indefinitely."
                    ),
                    recommendation=(
                        "Enable the user risk policy: Entra ID > Security > Identity Protection "
                        "> User risk policy. Set risk level = High, Access = Allow with "
                        "password change required. "
                        "Notify affected users and their managers automatically."
                    ),
                    cwe="CWE-287",
                ))

        risky_sps = self._graph_get(
            "identityProtection/riskyServicePrincipals",
            params={
                "$filter": "isEnabled eq true and riskState eq 'atRisk'",
                "$select": "displayName,riskLevel,riskDetail,riskLastUpdatedDateTime",
                "$top": 50,
            },
            beta=True,
        )
        if risky_sps:
            high_sp = [s for s in risky_sps if s.get("riskLevel") == "high"]
            if high_sp:
                sample = ", ".join(s.get("displayName", "?") for s in high_sp[:5])
                self._add(Finding(
                    rule_id="M365-IDP-005",
                    name=f"High-risk service principals detected ({len(high_sp)})",
                    category="Identity Protection",
                    severity="CRITICAL",
                    file_path="identityProtection/riskyServicePrincipals",
                    line_num=None,
                    line_content=f"High-risk SPs: {sample}",
                    description=(
                        f"{len(high_sp)} service principal(s) are flagged as high risk. "
                        "Risky service principals may indicate compromised app credentials, "
                        "suspicious API activity, or use from anomalous locations. "
                        "A compromised service principal with broad permissions can access "
                        "all data it has been granted rights to."
                    ),
                    recommendation=(
                        "Investigate the risk detections for each flagged service principal. "
                        "Rotate credentials (client secrets/certificates) immediately. "
                        "Review and restrict the permissions granted to each application. "
                        "Enable Workload Identity Protection in Entra ID P2."
                    ),
                    cwe="CWE-287",
                ))

    # ==========================================================
    #  v2.0.0 — NEW CHECK GROUPS
    # ==========================================================

    # ----------------------------------------------------------
    # 14. Microsoft Secure Score
    # ----------------------------------------------------------
    def _check_secure_score(self):
        self._vprint("  [check] Microsoft Secure Score …")

        score_data = self._graph_get_single("security/secureScores", params={
            "$top": 1,
            "$select": "currentScore,maxScore,enabledServices,controlScores",
        })
        if not score_data:
            self._vprint("  [skip] Secure Score not accessible (SecurityEvents.Read.All required).")
            return

        current = score_data.get("currentScore", 0)
        max_score = score_data.get("maxScore", 1)
        pct = int(current * 100 / max_score) if max_score else 0

        if pct < 30:
            sev = "CRITICAL"
        elif pct < 50:
            sev = "HIGH"
        elif pct < 70:
            sev = "MEDIUM"
        else:
            sev = "LOW"

        if pct < 70:
            self._add(Finding(
                rule_id="M365-SCORE-001",
                name=f"Microsoft Secure Score is {pct}% ({current}/{max_score})",
                category="Secure Score",
                severity=sev,
                file_path="security/secureScores",
                line_num=None,
                line_content=f"currentScore = {current}, maxScore = {max_score}, percentage = {pct}%",
                description=(
                    f"The tenant's Microsoft Secure Score is {pct}% ({current} of "
                    f"{max_score} points). A score below 70% indicates significant gaps "
                    "in security configuration across identity, data, device, and app pillars. "
                    "Microsoft Secure Score benchmarks your tenant against recommended practices."
                ),
                recommendation=(
                    "Review the Secure Score improvement actions in Microsoft 365 Defender > "
                    "Secure Score > Improvement Actions. Focus on high-impact actions first: "
                    "MFA enforcement, legacy auth blocking, mailbox auditing, and admin MFA. "
                    "Target a Secure Score above 70% as a baseline."
                ),
                cwe="CWE-1188",
            ))

        # Check for high-impact unresolved improvement actions
        control_scores = score_data.get("controlScores", []) or []
        unresolved_critical = [
            c for c in control_scores
            if c.get("score", 0) == 0
            and c.get("maxScore", 0) >= 10
        ]
        if unresolved_critical:
            names = ", ".join(c.get("controlName", "?") for c in unresolved_critical[:5])
            self._add(Finding(
                rule_id="M365-SCORE-002",
                name=f"High-impact Secure Score actions not implemented ({len(unresolved_critical)})",
                category="Secure Score",
                severity="HIGH",
                file_path="security/secureScores",
                line_num=None,
                line_content=f"Unresolved high-impact controls: {names}",
                description=(
                    f"{len(unresolved_critical)} improvement action(s) worth 10+ points each "
                    "have not been implemented. These represent the highest-value security "
                    "improvements available in the tenant."
                ),
                recommendation=(
                    "Prioritise the listed improvement actions. Each is worth 10+ Secure "
                    "Score points and typically addresses a fundamental security gap. "
                    "Review in Microsoft 365 Defender > Secure Score > Improvement Actions."
                ),
                cwe="CWE-1188",
            ))

    # ----------------------------------------------------------
    # 15. Intune Device Compliance
    # ----------------------------------------------------------
    def _check_intune_compliance(self):
        self._vprint("  [check] Intune device compliance …")

        # Check compliance policies
        policies = self._graph_get(
            "deviceManagement/deviceCompliancePolicies",
            params={"$select": "id,displayName,platformType,lastModifiedDateTime"},
        )
        if not policies:
            self._add(Finding(
                rule_id="M365-INTUNE-001",
                name="No Intune device compliance policies configured",
                category="Intune: Device Compliance",
                severity="HIGH",
                file_path="deviceManagement/deviceCompliancePolicies",
                line_num=None,
                line_content="Device compliance policies = 0",
                description=(
                    "No device compliance policies are defined in Microsoft Intune. "
                    "Without compliance policies, there is no baseline for what constitutes "
                    "a healthy device. Conditional Access policies that require compliant "
                    "devices will have no criteria to evaluate against."
                ),
                recommendation=(
                    "Create compliance policies for each platform (Windows, iOS, Android, macOS): "
                    "require OS minimum version, disk encryption, antivirus, firewall enabled, "
                    "and screen lock. Mark non-compliant devices after a grace period and "
                    "block access via Conditional Access."
                ),
                cwe="CWE-284",
            ))
            return

        platforms_covered = {p.get("platformType", "") for p in policies}
        expected_platforms = {"windows10AndLater", "iOS", "android", "macOS"}
        missing = expected_platforms - platforms_covered
        if missing:
            self._add(Finding(
                rule_id="M365-INTUNE-002",
                name=f"Missing Intune compliance policies for platforms: {', '.join(sorted(missing))}",
                category="Intune: Device Compliance",
                severity="MEDIUM",
                file_path="deviceManagement/deviceCompliancePolicies",
                line_num=None,
                line_content=f"Covered: {', '.join(sorted(platforms_covered))} — Missing: {', '.join(sorted(missing))}",
                description=(
                    f"Compliance policies exist but do not cover all device platforms. "
                    f"Missing: {', '.join(sorted(missing))}. Devices on uncovered platforms "
                    "will not be evaluated for compliance, allowing potentially insecure "
                    "devices to access corporate resources."
                ),
                recommendation=(
                    "Create compliance policies for all platforms used in your organisation. "
                    "Even if a platform is not officially supported, create a basic policy "
                    "to ensure Intune evaluates those devices."
                ),
                cwe="CWE-284",
            ))

        # Check for non-compliant devices
        managed_devices = self._graph_get(
            "deviceManagement/managedDevices",
            params={
                "$select": "id,deviceName,complianceState,operatingSystem,osVersion,lastSyncDateTime",
                "$filter": "complianceState eq 'noncompliant'",
                "$top": 100,
            },
        )
        if managed_devices:
            os_counts: dict[str, int] = {}
            for d in managed_devices:
                os_name = d.get("operatingSystem", "Unknown")
                os_counts[os_name] = os_counts.get(os_name, 0) + 1
            os_summary = ", ".join(f"{k}={v}" for k, v in sorted(os_counts.items()))

            sev = "CRITICAL" if len(managed_devices) > 50 else "HIGH"
            self._add(Finding(
                rule_id="M365-INTUNE-003",
                name=f"Non-compliant managed devices detected ({len(managed_devices)})",
                category="Intune: Device Compliance",
                severity=sev,
                file_path="deviceManagement/managedDevices",
                line_num=None,
                line_content=f"Non-compliant devices: {os_summary}",
                description=(
                    f"{len(managed_devices)} managed device(s) are in a non-compliant state. "
                    "Non-compliant devices may have outdated OS versions, disabled encryption, "
                    "missing antivirus, or jailbroken/rooted status. If CA policies require "
                    "device compliance, these users may be blocked; if not, they access "
                    "corporate data from insecure devices."
                ),
                recommendation=(
                    "Investigate non-compliant devices in Intune > Devices > Compliance. "
                    "Notify affected users with remediation steps. Enforce Conditional Access "
                    "policies that block non-compliant devices after a grace period. "
                    "Set up automated compliance notifications."
                ),
                cwe="CWE-284",
            ))

        # Check for stale devices (not synced in 90+ days)
        stale_cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
        stale_devices = self._graph_get(
            "deviceManagement/managedDevices",
            params={
                "$select": "id,deviceName,lastSyncDateTime,operatingSystem",
                "$filter": f"lastSyncDateTime lt {stale_cutoff[:10]}",
                "$top": 100,
            },
        )
        if stale_devices:
            self._add(Finding(
                rule_id="M365-INTUNE-004",
                name=f"Stale managed devices not synced in 90+ days ({len(stale_devices)})",
                category="Intune: Device Hygiene",
                severity="MEDIUM",
                file_path="deviceManagement/managedDevices",
                line_num=None,
                line_content=f"Devices not synced >90 days = {len(stale_devices)}",
                description=(
                    f"{len(stale_devices)} managed device(s) have not synced with Intune "
                    "in over 90 days. Stale devices may belong to former employees, lost/stolen "
                    "devices, or decommissioned hardware. They inflate the device inventory "
                    "and may still have cached corporate data."
                ),
                recommendation=(
                    "Create a device cleanup rule in Intune to automatically retire devices "
                    "that haven't synced in 90 days. Review stale devices and perform remote "
                    "wipe if necessary. Investigate whether the devices are still in use."
                ),
                cwe="CWE-404",
            ))

    # ----------------------------------------------------------
    # 16. Data Loss Prevention & Sensitivity Labels
    # ----------------------------------------------------------
    def _check_dlp_and_labels(self):
        self._vprint("  [check] Data Loss Prevention & Sensitivity Labels …")

        # Check sensitivity labels
        labels = self._graph_get(
            "informationProtection/policy/labels",
            params={"$select": "id,name,description,isActive"},
            beta=True,
        )
        if not labels:
            self._add(Finding(
                rule_id="M365-DLP-001",
                name="No sensitivity labels configured in Microsoft Purview",
                category="Data Loss Prevention",
                severity="HIGH",
                file_path="informationProtection/policy/labels",
                line_num=None,
                line_content="Sensitivity labels = 0",
                description=(
                    "No sensitivity labels are configured in the tenant. Sensitivity labels "
                    "classify and protect documents and emails based on their content "
                    "(e.g., Confidential, Highly Confidential, Public). Without labels, "
                    "there is no automated mechanism to enforce encryption, watermarking, "
                    "or access restrictions on sensitive data."
                ),
                recommendation=(
                    "Create sensitivity labels in Microsoft Purview > Information Protection: "
                    "1. Public — no protection "
                    "2. Internal — header/footer marking "
                    "3. Confidential — encryption + restricted access "
                    "4. Highly Confidential — encryption + no forwarding + watermark. "
                    "Publish labels via label policies to all users. Enable auto-labeling "
                    "for common sensitive data patterns (credit cards, SSNs, etc.)."
                ),
                cwe="CWE-311",
            ))
        else:
            active_labels = [l for l in labels if l.get("isActive", True)]
            if len(active_labels) < 3:
                self._add(Finding(
                    rule_id="M365-DLP-002",
                    name=f"Only {len(active_labels)} sensitivity labels configured (minimum 3 recommended)",
                    category="Data Loss Prevention",
                    severity="MEDIUM",
                    file_path="informationProtection/policy/labels",
                    line_num=None,
                    line_content=f"Active labels: {', '.join(l.get('name', '?') for l in active_labels)}",
                    description=(
                        f"Only {len(active_labels)} sensitivity labels are active. A minimum of "
                        "3 labels (e.g., Public, Confidential, Highly Confidential) is recommended "
                        "to provide meaningful classification granularity."
                    ),
                    recommendation=(
                        "Review and expand your sensitivity label taxonomy. Ensure at minimum: "
                        "a public/unclassified label, an internal-use label, and a confidential "
                        "label with encryption. Add sub-labels for specific audiences if needed."
                    ),
                    cwe="CWE-311",
                ))

        # DLP policies check — manual verification
        self._add(Finding(
            rule_id="M365-DLP-003",
            name="Verify: DLP policies are configured for Exchange, SharePoint, OneDrive, and Teams",
            category="Data Loss Prevention",
            severity="HIGH",
            file_path="compliance/dlp",
            line_num=None,
            line_content="DLP policy configuration — manual verification via Purview portal",
            description=(
                "Data Loss Prevention (DLP) policies prevent sensitive information "
                "(credit card numbers, SSNs, health records, financial data) from being "
                "shared externally via email, SharePoint, OneDrive, or Teams. "
                "DLP policy status requires PowerShell: Get-DlpCompliancePolicy | Select Name,Mode,Enabled"
            ),
            recommendation=(
                "Configure DLP policies in Microsoft Purview > Data Loss Prevention: "
                "1. Create policies using built-in sensitive information types "
                "2. Apply to Exchange, SharePoint, OneDrive, and Teams "
                "3. Start in test mode (simulate) before enforcing "
                "4. Configure user notifications and admin alerts "
                "5. Block external sharing of documents containing >5 sensitive items."
            ),
            cwe="CWE-200",
        ))

    # ----------------------------------------------------------
    # 17. Microsoft Defender for Office 365
    # ----------------------------------------------------------
    def _check_defender_for_o365(self):
        self._vprint("  [check] Microsoft Defender for Office 365 …")

        # Anti-phishing policies — available via Security & Compliance PowerShell
        # Graph API has limited coverage; we flag manual verification items

        self._add(Finding(
            rule_id="M365-MDO-001",
            name="Verify: Anti-phishing policy with impersonation protection is enabled",
            category="Defender for Office 365",
            severity="HIGH",
            file_path="security/threatProtection",
            line_num=None,
            line_content="Anti-phishing impersonation protection — manual verification required",
            description=(
                "Microsoft Defender for Office 365 anti-phishing policies can detect "
                "impersonation of executive users and trusted domains. Without impersonation "
                "protection, attackers can send emails that appear to come from the CEO or "
                "CFO, tricking employees into transferring funds or sharing credentials. "
                "PowerShell: Get-AntiPhishPolicy | Select Name,Enabled,EnableTargetedUserProtection"
            ),
            recommendation=(
                "In Microsoft 365 Defender > Policies > Anti-phishing: "
                "1. Enable impersonation protection for VIP users (C-suite, finance, HR) "
                "2. Enable domain impersonation protection for your tenant domains "
                "3. Set action to quarantine impersonated messages "
                "4. Enable mailbox intelligence for enhanced detection "
                "5. Enable first-contact safety tips."
            ),
            cwe="CWE-290",
        ))

        self._add(Finding(
            rule_id="M365-MDO-002",
            name="Verify: Safe Links policy is enabled for Office 365 apps and email",
            category="Defender for Office 365",
            severity="HIGH",
            file_path="security/safeLinks",
            line_num=None,
            line_content="Safe Links policy — manual verification required",
            description=(
                "Safe Links provides time-of-click URL scanning and rewriting in emails "
                "and Office documents. Without Safe Links, users who click malicious URLs "
                "are taken directly to phishing sites or malware downloads. "
                "PowerShell: Get-SafeLinksPolicy | Select Name,IsEnabled,EnableForInternalSenders"
            ),
            recommendation=(
                "Enable Safe Links in Microsoft 365 Defender > Policies > Safe Links: "
                "1. Apply to all users (not just specific groups) "
                "2. Enable URL scanning in email messages "
                "3. Enable Safe Links for Office 365 apps (Word, Excel, PowerPoint, Teams) "
                "4. Do not allow users to click through to the original URL "
                "5. Enable real-time URL scanning before delivering the message."
            ),
            cwe="CWE-601",
        ))

        self._add(Finding(
            rule_id="M365-MDO-003",
            name="Verify: Safe Attachments policy is enabled for SharePoint, OneDrive, and Teams",
            category="Defender for Office 365",
            severity="HIGH",
            file_path="security/safeAttachments",
            line_num=None,
            line_content="Safe Attachments policy — manual verification required",
            description=(
                "Safe Attachments detonates email attachments in a sandbox to detect "
                "zero-day malware. Without it, novel malware in attachments bypasses "
                "signature-based scanning. Also verify that Safe Attachments for "
                "SharePoint, OneDrive, and Teams is enabled (separate toggle). "
                "PowerShell: Get-SafeAttachmentPolicy | Select Name,Enable,Action"
            ),
            recommendation=(
                "Enable Safe Attachments in Microsoft 365 Defender > Policies > Safe Attachments: "
                "1. Set action to 'Dynamic Delivery' (delivers email immediately, replaces "
                "   attachments with placeholders until scanning completes) "
                "2. Enable Safe Attachments for SharePoint, OneDrive, and Teams "
                "3. Enable redirect to a security mailbox for blocked attachments "
                "4. Apply to all users."
            ),
            cwe="CWE-434",
        ))

        self._add(Finding(
            rule_id="M365-MDO-004",
            name="Verify: Zero-hour Auto Purge (ZAP) is enabled for email",
            category="Defender for Office 365",
            severity="MEDIUM",
            file_path="security/threatProtection",
            line_num=None,
            line_content="Zero-hour Auto Purge — manual verification required",
            description=(
                "Zero-hour Auto Purge (ZAP) retroactively moves already-delivered emails "
                "to quarantine or junk when they are later identified as malicious. Without "
                "ZAP, a phishing email delivered before its URL was classified remains in "
                "the user's inbox indefinitely. "
                "PowerShell: Get-MalwareFilterPolicy | Select Name,ZapEnabled"
            ),
            recommendation=(
                "Verify ZAP is enabled for phishing and malware in Exchange Online: "
                "Set-MalwareFilterPolicy -Identity Default -ZapEnabled $true. "
                "Also verify anti-spam ZAP: "
                "Set-HostedContentFilterPolicy -Identity Default -SpamZapEnabled $true "
                "-PhishZapEnabled $true."
            ),
            cwe="CWE-799",
        ))

    # ----------------------------------------------------------
    # 18. Token Lifetime & Session Policies
    # ----------------------------------------------------------
    def _check_token_session_policies(self):
        self._vprint("  [check] Token lifetime and session policies …")

        # Check CA policies for sign-in frequency and persistent browser controls
        ca_policies = self._graph_get("identity/conditionalAccessPolicies")
        if not ca_policies:
            return

        enabled = [p for p in ca_policies if p.get("state") == "enabled"]
        has_sign_in_frequency = False
        has_persistent_browser = False

        for p in enabled:
            session = p.get("sessionControls") or {}

            sif = session.get("signInFrequency") or {}
            if sif.get("isEnabled", False):
                has_sign_in_frequency = True

            pb = session.get("persistentBrowser") or {}
            if pb.get("isEnabled", False):
                has_persistent_browser = True

        if not has_sign_in_frequency:
            self._add(Finding(
                rule_id="M365-SESSION-001",
                name="No Conditional Access policy enforces sign-in frequency",
                category="Session Security",
                severity="MEDIUM",
                file_path="identity/conditionalAccessPolicies",
                line_num=None,
                line_content="Sign-in frequency control = not configured in any enforced CA policy",
                description=(
                    "No CA policy configures a sign-in frequency control. Without this, "
                    "users remain authenticated based on the default token lifetime "
                    "(up to 90 days for refresh tokens). If a session token is stolen, "
                    "the attacker can use it for the full token lifetime without re-authentication."
                ),
                recommendation=(
                    "Create a CA policy with sign-in frequency for sensitive apps: "
                    "1. For admin portals: sign-in frequency = 4 hours "
                    "2. For sensitive data apps: sign-in frequency = 8-12 hours "
                    "3. For general access: sign-in frequency = 24 hours "
                    "Consider 'every time' for high-security scenarios."
                ),
                cwe="CWE-613",
            ))

        if not has_persistent_browser:
            self._add(Finding(
                rule_id="M365-SESSION-002",
                name="No Conditional Access policy controls persistent browser sessions",
                category="Session Security",
                severity="LOW",
                file_path="identity/conditionalAccessPolicies",
                line_num=None,
                line_content="Persistent browser session control = not configured",
                description=(
                    "No CA policy manages persistent browser sessions (the 'Keep me signed in' "
                    "functionality). Without this control, users who check 'Keep me signed in' "
                    "on shared or unmanaged devices leave long-lived sessions that anyone "
                    "with physical access can use."
                ),
                recommendation=(
                    "Create a CA policy to disable persistent browser sessions for "
                    "unmanaged/non-compliant devices: Session controls > Persistent browser "
                    "session = Never persistent. Allow persistent sessions only for "
                    "Intune-compliant or hybrid-joined devices."
                ),
                cwe="CWE-613",
            ))

        # Check token lifetime policies (custom policies that weaken defaults)
        token_policies = self._graph_get(
            "policies/tokenLifetimePolicies",
            params={"$select": "id,displayName,definition,isOrganizationDefault"},
        )
        for tp in token_policies:
            definitions = tp.get("definition", []) or []
            name = tp.get("displayName", "?")
            for defn_str in definitions:
                try:
                    defn = json.loads(defn_str) if isinstance(defn_str, str) else defn_str
                except (json.JSONDecodeError, TypeError):
                    continue
                token_config = defn.get("TokenLifetimePolicy", {})
                access_token_lifetime = token_config.get("AccessTokenLifetime")
                if access_token_lifetime:
                    # Parse ISO 8601 duration heuristically
                    hours_match = re.search(r"(\d+)H", str(access_token_lifetime), re.IGNORECASE)
                    if hours_match and int(hours_match.group(1)) > 4:
                        self._add(Finding(
                            rule_id="M365-SESSION-003",
                            name=f"Token lifetime policy '{name}' extends access token beyond 4 hours",
                            category="Session Security",
                            severity="MEDIUM",
                            file_path="policies/tokenLifetimePolicies",
                            line_num=None,
                            line_content=f"AccessTokenLifetime = {access_token_lifetime}",
                            description=(
                                f"Custom token lifetime policy '{name}' sets access token "
                                f"lifetime to {access_token_lifetime}. Extended access token "
                                "lifetimes increase the window during which a stolen token "
                                "can be used without re-authentication."
                            ),
                            recommendation=(
                                "Reduce access token lifetime to 1 hour (default) or less. "
                                "Use Continuous Access Evaluation (CAE) to revoke tokens in "
                                "near-real-time when critical events occur (password change, "
                                "user disabled, location change)."
                            ),
                            cwe="CWE-613",
                        ))

    # ----------------------------------------------------------
    # 19. Cross-Tenant Access Settings
    # ----------------------------------------------------------
    def _check_cross_tenant_access(self):
        self._vprint("  [check] Cross-tenant access settings …")

        default_policy = self._graph_get_single(
            "policies/crossTenantAccessPolicy/default",
        )
        if not default_policy:
            self._vprint("  [skip] Cross-tenant access policy not accessible.")
            return

        # Check inbound trust settings — does this tenant trust MFA from other tenants?
        inbound = default_policy.get("inboundTrust", {}) or {}
        trust_mfa = inbound.get("isMfaAccepted", False)
        trust_compliant = inbound.get("isCompliantDeviceAccepted", False)
        trust_hybrid = inbound.get("isHybridAzureADJoinedDeviceAccepted", False)

        if trust_mfa:
            self._add(Finding(
                rule_id="M365-XTA-001",
                name="Default cross-tenant policy trusts MFA from all external tenants",
                category="Cross-Tenant Access",
                severity="HIGH",
                file_path="policies/crossTenantAccessPolicy/default",
                line_num=None,
                line_content="inboundTrust.isMfaAccepted = true (default for all tenants)",
                description=(
                    "The default cross-tenant access policy trusts MFA claims from all "
                    "external Entra ID tenants. This means if a user from any external tenant "
                    "claims to have completed MFA, your tenant accepts that claim without "
                    "re-verification. A compromised external tenant could forge MFA claims."
                ),
                recommendation=(
                    "Do not trust MFA from all tenants by default. Set isMfaAccepted = false "
                    "in the default policy. Create partner-specific cross-tenant policies "
                    "that trust MFA only for verified partner organisations. "
                    "Configure in Entra ID > External Identities > Cross-tenant access settings."
                ),
                cwe="CWE-287",
            ))

        if trust_compliant and trust_hybrid:
            self._add(Finding(
                rule_id="M365-XTA-002",
                name="Default cross-tenant policy trusts device compliance from all external tenants",
                category="Cross-Tenant Access",
                severity="MEDIUM",
                file_path="policies/crossTenantAccessPolicy/default",
                line_num=None,
                line_content=f"isCompliantDeviceAccepted = {trust_compliant}, isHybridAzureADJoinedDeviceAccepted = {trust_hybrid}",
                description=(
                    "The default policy trusts device compliance and hybrid join claims from "
                    "all external tenants. External tenants may have different compliance "
                    "standards or insecure device configurations that don't meet your "
                    "organisation's requirements."
                ),
                recommendation=(
                    "Disable default device trust: set isCompliantDeviceAccepted = false "
                    "and isHybridAzureADJoinedDeviceAccepted = false in the default policy. "
                    "Only trust device claims from specific verified partner tenants."
                ),
                cwe="CWE-284",
            ))

        # Check B2B collaboration — outbound settings
        outbound = default_policy.get("b2bCollaborationOutbound", {}) or {}
        outbound_apps = outbound.get("applications", {}) or {}
        outbound_access_type = outbound_apps.get("accessType", "")
        if outbound_access_type == "allowed":
            target_apps = outbound_apps.get("targets", []) or []
            all_apps = any(
                t.get("target") == "AllApplications"
                for t in target_apps
            )
            if all_apps:
                self._add(Finding(
                    rule_id="M365-XTA-003",
                    name="Default outbound B2B collaboration allows access to all external apps",
                    category="Cross-Tenant Access",
                    severity="MEDIUM",
                    file_path="policies/crossTenantAccessPolicy/default",
                    line_num=None,
                    line_content="b2bCollaborationOutbound.applications = AllApplications (allowed)",
                    description=(
                        "The default cross-tenant policy allows your users to access all "
                        "applications in any external tenant via B2B collaboration. This means "
                        "your users can be invited to any external tenant and access their "
                        "resources, potentially exposing corporate credentials to untrusted tenants."
                    ),
                    recommendation=(
                        "Restrict outbound B2B collaboration to specific trusted partner tenants. "
                        "Block outbound access by default and allowlist only approved organisations. "
                        "Monitor outbound collaboration via Entra ID sign-in logs."
                    ),
                    cwe="CWE-284",
                ))

    # ----------------------------------------------------------
    # 20. Admin Consent Workflow & OAuth App Governance
    # ----------------------------------------------------------
    def _check_admin_consent_workflow(self):
        self._vprint("  [check] Admin consent workflow and OAuth governance …")

        auth_policy = self._graph_get_single("policies/authorizationPolicy")
        if not auth_policy:
            return

        # M365-CONSENT-001: Users can consent to apps on their own
        default_consent = auth_policy.get("defaultUserRolePermissions", {})
        user_consent_allowed = default_consent.get("permissionGrantPoliciesAssigned", [])
        # If ManagePermissionGrantsForSelf.microsoft-user-default-legacy is present,
        # users can consent to any app
        allows_user_consent = any(
            "user-default-legacy" in str(p).lower() or
            "user-default-low" in str(p).lower()
            for p in user_consent_allowed
        ) if user_consent_allowed else True  # Default in most tenants

        if allows_user_consent:
            self._add(Finding(
                rule_id="M365-CONSENT-001",
                name="Users can grant consent to third-party applications",
                category="OAuth App Governance",
                severity="HIGH",
                file_path="policies/authorizationPolicy",
                line_num=None,
                line_content=f"permissionGrantPoliciesAssigned = {user_consent_allowed}",
                description=(
                    "Users can consent to third-party OAuth applications requesting access "
                    "to their data (email, calendar, files). This is a primary vector for "
                    "OAuth phishing attacks: an attacker creates a malicious app, tricks a "
                    "user into consenting, and gains persistent API access to the user's "
                    "mailbox and files without needing their password."
                ),
                recommendation=(
                    "Disable user consent: Entra ID > Enterprise applications > Consent and "
                    "permissions > User consent settings > 'Do not allow user consent'. "
                    "Enable the admin consent workflow so users can request app access "
                    "and admins review each request. Alternatively, allow consent only "
                    "for apps from verified publishers."
                ),
                cwe="CWE-284",
            ))

        # M365-CONSENT-002: Admin consent workflow
        admin_consent_settings = self._graph_get_single(
            "policies/adminConsentRequestPolicy",
        )
        if admin_consent_settings:
            is_enabled = admin_consent_settings.get("isEnabled", False)
            if not is_enabled:
                self._add(Finding(
                    rule_id="M365-CONSENT-002",
                    name="Admin consent request workflow is not enabled",
                    category="OAuth App Governance",
                    severity="MEDIUM",
                    file_path="policies/adminConsentRequestPolicy",
                    line_num=None,
                    line_content="adminConsentRequestPolicy.isEnabled = false",
                    description=(
                        "The admin consent workflow is not enabled. Without it, users who "
                        "need to use a third-party app that requires consent have no formal "
                        "process to request admin approval. This often leads to shadow IT "
                        "or users finding workarounds that bypass security controls."
                    ),
                    recommendation=(
                        "Enable the admin consent workflow: Entra ID > Enterprise applications > "
                        "Admin consent requests > Settings > Enable admin consent requests. "
                        "Designate security-aware reviewers who can evaluate the permissions "
                        "requested by each application."
                    ),
                    cwe="CWE-284",
                ))

        # M365-CONSENT-003: Check for over-privileged service principals
        sps = self._graph_get(
            "servicePrincipals",
            params={
                "$select": "id,displayName,appId,appRoleAssignments,servicePrincipalType,verifiedPublisher",
                "$filter": "servicePrincipalType eq 'Application'",
                "$top": 500,
            },
        )
        unverified_with_perms = []
        for sp in sps:
            publisher = sp.get("verifiedPublisher", {}) or {}
            if not publisher.get("displayName"):
                # Unverified publisher — check if it has app role assignments
                assignments = self._graph_get(
                    f"servicePrincipals/{sp['id']}/appRoleAssignments",
                    params={"$top": 5},
                )
                if assignments:
                    unverified_with_perms.append(sp.get("displayName", "?"))

        if unverified_with_perms:
            sample = ", ".join(unverified_with_perms[:5])
            suffix = f" (+{len(unverified_with_perms)-5} more)" if len(unverified_with_perms) > 5 else ""
            self._add(Finding(
                rule_id="M365-CONSENT-003",
                name=f"Unverified publisher apps with granted permissions ({len(unverified_with_perms)})",
                category="OAuth App Governance",
                severity="HIGH",
                file_path="servicePrincipals",
                line_num=None,
                line_content=f"Unverified apps: {sample}{suffix}",
                description=(
                    f"{len(unverified_with_perms)} application(s) from unverified publishers "
                    "have been granted permissions in your tenant. Unverified publishers have "
                    "not completed Microsoft's publisher verification process, making it harder "
                    "to assess trust. These apps may be legitimate but could also be malicious "
                    "OAuth phishing apps."
                ),
                recommendation=(
                    "Review each unverified application in Entra ID > Enterprise applications. "
                    "Verify the publisher's identity and the app's business purpose. "
                    "Remove consent for apps that are not recognised or no longer needed. "
                    "Implement a policy requiring publisher verification for all new app consents."
                ),
                cwe="CWE-284",
            ))

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------
    def _add(self, finding: Finding):
        self.findings.append(finding)

    def _vprint(self, msg: str):
        if self.verbose:
            print(msg)

    def _warn(self, msg: str):
        print(f"  [!] {msg}", file=sys.stderr)

    # ----------------------------------------------------------
    # Reporting
    # ----------------------------------------------------------
    def summary(self) -> dict:
        counts = {s: 0 for s in self.SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def filter_severity(self, min_severity: str):
        threshold = self.SEVERITY_ORDER.get(min_severity, 4)
        self.findings = [
            f for f in self.findings
            if self.SEVERITY_ORDER.get(f.severity, 4) <= threshold
        ]

    def print_report(self):
        B, R = self.BOLD, self.RESET
        print(f"\n{B}{'='*72}{R}")
        print(f"{B}  Microsoft 365 SSPM Scanner v{VERSION}  --  Scan Report{R}")
        print(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Tenant    : {self._org_name} ({self.tenant_id})")
        print(f"  Findings  : {len(self.findings)}")
        print(f"{B}{'='*72}{R}\n")

        if not self.findings:
            print("  [+] No issues found.\n")
            return

        sorted_findings = sorted(
            self.findings,
            key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 4), f.category, f.rule_id),
        )

        for f in sorted_findings:
            sev_color = self.SEVERITY_COLOR.get(f.severity, "")
            print(f"{sev_color}{B}[{f.severity}]{R}  {f.rule_id}  {f.name}")
            print(f"  Endpoint : {f.file_path}")
            print(f"  Context  : {f.line_content}")
            if f.cwe:
                print(f"  CWE      : {f.cwe}")
            print(f"  Issue    : {f.description}")
            print(f"  Fix      : {f.recommendation}")
            print()

        counts = self.summary()
        print(f"{B}{'='*72}{R}")
        print(f"{B}  SUMMARY{R}")
        print("=" * 72)
        for sev, _ in sorted(self.SEVERITY_ORDER.items(), key=lambda x: x[1]):
            color = self.SEVERITY_COLOR.get(sev, "")
            print(f"  {color}{sev:<10}{R}  {counts.get(sev, 0)}")
        print("=" * 72)

    def save_json(self, path: str):
        report = {
            "scanner": "o365_scanner",
            "version": VERSION,
            "generated": datetime.now().isoformat(),
            "tenant_id": self.tenant_id,
            "tenant_name": self._org_name,
            "findings_count": len(self.findings),
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\n[+] JSON report saved to: {os.path.abspath(path)}")

    def save_html(self, path: str):
        esc = html_mod.escape
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        counts = self.summary()

        sev_style = {
            "CRITICAL": "background:#c0392b;color:#fff",
            "HIGH":     "background:#e67e22;color:#fff",
            "MEDIUM":   "background:#2980b9;color:#fff",
            "LOW":      "background:#27ae60;color:#fff",
        }
        row_style = {
            "CRITICAL": "border-left:4px solid #c0392b",
            "HIGH":     "border-left:4px solid #e67e22",
            "MEDIUM":   "border-left:4px solid #2980b9",
            "LOW":      "border-left:4px solid #27ae60",
        }

        sorted_findings = sorted(
            self.findings,
            key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 4), f.category, f.rule_id),
        )

        chip_html = ""
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            c = counts.get(sev, 0)
            st = sev_style[sev]
            chip_html += (
                f'<span style="{st};padding:4px 14px;border-radius:12px;'
                f'font-weight:bold;font-size:0.9em;margin:0 6px">'
                f'{esc(sev)}: {c}</span>'
            )

        rows_html = ""
        for i, f in enumerate(sorted_findings):
            bg = "#1e1e2e" if i % 2 == 0 else "#252535"
            rs = row_style.get(f.severity, "")
            st = sev_style.get(f.severity, "")
            rows_html += (
                f'<tr style="background:{bg};{rs}" '
                f'data-severity="{esc(f.severity)}" data-category="{esc(f.category)}">'
                f'<td style="padding:10px 14px">'
                f'<span style="{st};padding:3px 10px;border-radius:10px;'
                f'font-size:0.8em;font-weight:bold">{esc(f.severity)}</span></td>'
                f'<td style="padding:10px 14px;font-family:monospace;font-size:0.9em">'
                f'{esc(f.rule_id)}</td>'
                f'<td style="padding:10px 14px;color:#a9b1d6">{esc(f.category)}</td>'
                f'<td style="padding:10px 14px;font-weight:bold;color:#cdd6f4">'
                f'{esc(f.name)}</td>'
                f'<td style="padding:10px 14px;font-family:monospace;font-size:0.85em;'
                f'color:#89b4fa">{esc(f.file_path)}</td>'
                f'<td style="padding:10px 14px;font-family:monospace;font-size:0.82em;'
                f'color:#a6e3a1">{esc(f.line_content or "")}</td>'
                f'<td style="padding:10px 14px;color:#cdd6f4">{esc(f.cwe)}</td>'
                f'</tr>'
                f'<tr style="background:{bg}" data-severity="{esc(f.severity)}" '
                f'data-category="{esc(f.category)}">'
                f'<td colspan="7" style="padding:6px 14px 14px 14px">'
                f'<div style="color:#bac2de;font-size:0.88em;margin-bottom:4px">'
                f'<b>Issue:</b> {esc(f.description)}</div>'
                f'<div style="color:#89dceb;font-size:0.88em">'
                f'<b>Fix:</b> {esc(f.recommendation)}</div>'
                f'</td></tr>'
            )

        categories = sorted({f.category for f in self.findings})
        cat_options = "".join(
            f'<option value="{esc(c)}">{esc(c)}</option>' for c in categories
        )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Microsoft 365 SSPM Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1b2e; color: #cdd6f4; }}
  header {{ background: linear-gradient(135deg,#0078d4 0%,#1a1b2e 100%);
            padding: 28px 36px; border-bottom: 2px solid #313244; }}
  header h1 {{ font-size: 1.7em; font-weight: 700; color: #fff; margin-bottom: 8px; }}
  header .meta {{ color: #b0c4de; font-size: 0.95em; margin: 3px 0; }}
  .chips {{ padding: 20px 36px; background: #181825;
            border-bottom: 1px solid #313244;
            display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }}
  .chips label {{ color: #a6adc8; font-size: 0.9em; margin-right: 6px; }}
  .filters {{ padding: 16px 36px; background: #1e1e2e;
              display: flex; gap: 12px; flex-wrap: wrap;
              border-bottom: 1px solid #313244; }}
  .filters select, .filters input {{
    background: #313244; color: #cdd6f4;
    border: 1px solid #45475a; border-radius: 6px;
    padding: 6px 12px; font-size: 0.9em; }}
  .container {{ padding: 20px 36px 40px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.92em; }}
  th {{ background: #0078d4; color: #fff; padding: 12px 14px;
        text-align: left; font-weight: 600; position: sticky; top: 0; }}
  tr:hover td {{ filter: brightness(1.1); }}
  td {{ vertical-align: top; }}
  .no-findings {{ text-align: center; padding: 60px;
                 color: #a6e3a1; font-size: 1.2em; }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:10px;
            font-size:0.78em; font-weight:bold; margin-right:4px; }}
</style>
</head>
<body>
<header>
  <h1>Microsoft 365 SSPM Scan Report</h1>
  <p class="meta">Scanner: O365 SSPM Scanner v{esc(VERSION)}</p>
  <p class="meta">Tenant: {esc(self._org_name)} ({esc(self.tenant_id)})</p>
  <p class="meta">Generated: {esc(now)}</p>
  <p class="meta">Total Findings: <strong>{len(self.findings)}</strong></p>
</header>
<div class="chips">
  <label>Severity:</label>
  {chip_html}
</div>
<div class="filters">
  <select id="sevFilter" onchange="applyFilters()">
    <option value="">All Severities</option>
    <option>CRITICAL</option><option>HIGH</option>
    <option>MEDIUM</option><option>LOW</option>
  </select>
  <select id="catFilter" onchange="applyFilters()">
    <option value="">All Categories</option>
    {cat_options}
  </select>
  <input type="text" id="txtFilter" placeholder="Search …"
         oninput="applyFilters()" style="flex:1;min-width:200px">
</div>
<div class="container">
{"<div class='no-findings'>No findings - tenant is clean!</div>" if not self.findings else f'''
<table id="ft">
<thead><tr>
  <th>Severity</th><th>Rule ID</th><th>Category</th><th>Finding</th>
  <th>Endpoint</th><th>Context</th><th>CWE</th>
</tr></thead>
<tbody>{rows_html}</tbody>
</table>'''}
</div>
<script>
function applyFilters(){{
  var sv=document.getElementById('sevFilter').value.toUpperCase();
  var ca=document.getElementById('catFilter').value.toLowerCase();
  var tx=document.getElementById('txtFilter').value.toLowerCase();
  document.querySelectorAll('#ft tbody tr').forEach(function(r){{
    var rs=(r.getAttribute('data-severity')||'').toUpperCase();
    var rc=(r.getAttribute('data-category')||'').toLowerCase();
    var rt=r.textContent.toLowerCase();
    r.style.display=(!sv||rs===sv)&&(!ca||rc.includes(ca))&&(!tx||rt.includes(tx))?'':'none';
  }});
}}
</script>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        print(f"\n[+] HTML report saved to: {os.path.abspath(path)}")


# ============================================================
# CLI entry point
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        prog="o365_scanner",
        description=(
            f"Microsoft 365 SSPM Scanner v{VERSION} — "
            "Comprehensive SaaS Security Posture Management via Microsoft Graph API"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Required Microsoft Graph Application Permissions (read-only):\n"
            "  Organization.Read.All              Policy.Read.All\n"
            "  Directory.Read.All                 User.Read.All\n"
            "  AuditLog.Read.All                  IdentityRiskyUser.Read.All\n"
            "  Application.Read.All               RoleManagement.Read.All\n"
            "  Reports.Read.All                   UserAuthenticationMethod.Read.All\n"
            "  PrivilegedAccess.Read.AzureAD      SharePointTenantSettings.Read.All\n"
            "  SecurityEvents.Read.All            DeviceManagementConfiguration.Read.All\n"
            "  DeviceManagementManagedDevices.Read.All\n"
            "  InformationProtectionPolicy.Read.All\n"
            "  CrossTenantInformation.ReadBasic.All\n\n"
            "Environment variables: M365_TENANT_ID  M365_CLIENT_ID  M365_CLIENT_SECRET"
        ),
    )
    parser.add_argument(
        "--tenant-id", "-t",
        default=os.environ.get("M365_TENANT_ID", ""),
        metavar="TENANT_ID",
        help="Entra ID tenant ID (GUID) or primary domain. Env: M365_TENANT_ID",
    )
    parser.add_argument(
        "--client-id", "-c",
        default=os.environ.get("M365_CLIENT_ID", ""),
        metavar="CLIENT_ID",
        help="App Registration client (application) ID. Env: M365_CLIENT_ID",
    )
    parser.add_argument(
        "--client-secret", "-s",
        default=os.environ.get("M365_CLIENT_SECRET", ""),
        metavar="SECRET",
        help="App Registration client secret. Env: M365_CLIENT_SECRET",
    )
    parser.add_argument(
        "--severity",
        default="LOW",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Minimum severity to report (default: LOW)",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Save findings as JSON to FILE",
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Save findings as self-contained HTML to FILE",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output (API calls, skipped endpoints, etc.)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"o365_scanner v{VERSION}",
    )

    args = parser.parse_args()

    if not HAS_REQUESTS:
        parser.error(
            "The 'requests' library is required.\n"
            "  Install with:  pip install requests"
        )

    missing = []
    if not args.tenant_id:
        missing.append("--tenant-id (or M365_TENANT_ID env var)")
    if not args.client_id:
        missing.append("--client-id (or M365_CLIENT_ID env var)")
    if not args.client_secret:
        missing.append("--client-secret (or M365_CLIENT_SECRET env var)")
    if missing:
        parser.error("Missing required arguments:\n  " + "\n  ".join(missing))

    scanner = O365Scanner(
        tenant_id=args.tenant_id,
        client_id=args.client_id,
        client_secret=args.client_secret,
        verbose=args.verbose,
    )

    scanner.scan()
    scanner.filter_severity(args.severity)
    scanner.print_report()

    if args.json:
        scanner.save_json(args.json)
    if args.html:
        scanner.save_html(args.html)

    has_critical_high = any(
        f.severity in ("CRITICAL", "HIGH") for f in scanner.findings
    )
    sys.exit(1 if has_critical_high else 0)


if __name__ == "__main__":
    main()
