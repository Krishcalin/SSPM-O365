#!/usr/bin/env python3
"""Generate synthetic O365 SSPM reports without live API connections."""
import sys
import os

# Add the scanner directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from o365_scanner import O365Scanner, Finding

def main():
    # Create scanner instance with dummy credentials (we won't call scan())
    scanner = O365Scanner.__new__(O365Scanner)
    scanner.tenant_id = "demo-tenant-00000000-0000-0000-0000-000000000000"
    scanner.client_id = "demo-client-id"
    scanner.client_secret = "***"
    scanner.verbose = False
    scanner.findings = []
    scanner._token = ""
    scanner._org_name = "Contoso Corp (Demo)"

    # Inject synthetic findings across all categories
    synthetic_findings = [
        # Identity & MFA
        Finding("M365-MFA-001", "MFA not enforced for all users",
                "Identity & MFA", "CRITICAL",
                "/identity/conditionalAccess", None,
                "MFA enforcement = Disabled for 23% of users",
                "Multi-Factor Authentication is not enforced for all users, leaving accounts vulnerable to credential attacks.",
                "Enable MFA via Conditional Access policies for all users. Start with Security Defaults if no CA license."),
        Finding("M365-MFA-002", "Admins without phishing-resistant MFA",
                "Identity & MFA", "CRITICAL",
                "/identity/authenticationMethods", None,
                "Global Admins without FIDO2/CBA: admin@contoso.com, itadmin@contoso.com",
                "Privileged accounts lack phishing-resistant authentication methods (FIDO2 or Certificate-Based Auth).",
                "Require phishing-resistant MFA (FIDO2 security keys or CBA) for all admin roles via Conditional Access."),
        Finding("M365-MFA-003", "Legacy per-user MFA still in use",
                "Identity & MFA", "MEDIUM",
                "/identity/conditionalAccess", None,
                "Per-user MFA enabled for 5 users (should use CA policies)",
                "Legacy per-user MFA is harder to manage and lacks Conditional Access features like device compliance.",
                "Migrate from per-user MFA to Conditional Access-based MFA enforcement."),

        # Conditional Access
        Finding("M365-CA-001", "No Conditional Access policies defined",
                "Conditional Access", "HIGH",
                "/identity/conditionalAccess/policies", None,
                "Active CA policies = 0",
                "No Conditional Access policies are configured, meaning all sign-ins are allowed without risk-based controls.",
                "Create baseline CA policies: require MFA, block legacy auth, require compliant devices for sensitive apps."),
        Finding("M365-CA-002", "Legacy authentication not blocked",
                "Conditional Access", "HIGH",
                "/identity/conditionalAccess/policies", None,
                "Block legacy auth policy = Not found",
                "Legacy protocols (IMAP, POP3, SMTP) bypass MFA and are commonly exploited in password spray attacks.",
                "Create a CA policy to block legacy authentication for all users."),
        Finding("M365-CA-003", "No sign-in risk policy",
                "Conditional Access", "MEDIUM",
                "/identity/conditionalAccess/policies", None,
                "Sign-in risk CA policy = Not configured",
                "No policy responds to risky sign-ins (e.g., from anonymous IP, impossible travel).",
                "Enable a sign-in risk CA policy requiring MFA for medium/high risk sign-ins."),

        # Privileged Access
        Finding("M365-PRIV-001", "Excessive Global Administrators",
                "Privileged Access", "HIGH",
                "/directoryRoles/GlobalAdmin/members", None,
                "Global Admins: 8 (recommended: <= 4)",
                "Too many Global Administrators increases the blast radius of a compromised admin account.",
                "Reduce Global Admin count to 2-4. Use least-privilege roles (e.g., Exchange Admin, SharePoint Admin)."),
        Finding("M365-PRIV-002", "PIM not enabled for privileged roles",
                "Privileged Access", "HIGH",
                "/privilegedAccess/aadroles", None,
                "PIM-managed roles = 0 of 12 privileged roles",
                "Privileged Identity Management provides just-in-time access and approval workflows for admin roles.",
                "Enable PIM for all privileged directory roles. Require approval and justification for activation."),
        Finding("M365-PRIV-003", "Guest users in privileged roles",
                "Privileged Access", "CRITICAL",
                "/directoryRoles/members", None,
                "Guest admins: guest-vendor@partner.com (Security Admin)",
                "External guest accounts should never hold privileged directory roles.",
                "Remove guest accounts from all privileged roles immediately."),

        # Exchange Online
        Finding("M365-EXO-001", "SMTP AUTH enabled globally",
                "Exchange Online", "MEDIUM",
                "/admin/exchangeSettings", None,
                "SmtpAuth = Enabled (organization-wide)",
                "SMTP AUTH allows legacy basic auth for email sending, which can be exploited for credential theft.",
                "Disable SMTP AUTH at the organization level. Enable per-mailbox only where required."),
        Finding("M365-EXO-002", "Mailbox audit logging not enabled for all",
                "Exchange Online", "MEDIUM",
                "/admin/exchangeSettings", None,
                "Mailbox audit = Disabled for 12 mailboxes",
                "Without audit logging, mailbox access by admins or delegates cannot be tracked.",
                "Enable mailbox auditing for all mailboxes (now on by default for new tenants)."),

        # SharePoint & OneDrive
        Finding("M365-SPO-001", "External sharing set to 'Anyone' links",
                "SharePoint & OneDrive", "HIGH",
                "/admin/sharepoint/settings", None,
                "SharingCapability = ExternalUserAndGuestSharing (Anyone)",
                "Anyone links allow unauthenticated access to shared files and folders.",
                "Restrict sharing to 'New and existing guests' or 'Existing guests only'. Require sign-in for external access."),
        Finding("M365-SPO-002", "OneDrive sync not restricted to managed devices",
                "SharePoint & OneDrive", "MEDIUM",
                "/admin/onedrive/settings", None,
                "AllowSyncOnUnmanagedDevices = True",
                "Users can sync corporate data to unmanaged personal devices.",
                "Restrict OneDrive sync to domain-joined or Intune-compliant devices."),

        # Teams
        Finding("M365-TEAMS-001", "External access allows all domains",
                "Microsoft Teams", "MEDIUM",
                "/admin/teams/externalAccess", None,
                "AllowedDomains = All (no restrictions)",
                "Any external Teams user can communicate with your organization.",
                "Restrict external access to specific trusted domains or disable if not needed."),

        # Compliance & Audit
        Finding("M365-COMP-001", "Unified audit log not enabled",
                "Compliance & Audit", "HIGH",
                "/security/auditLog", None,
                "UnifiedAuditLog = Disabled",
                "The unified audit log is essential for security investigations and compliance.",
                "Enable the unified audit log in the Microsoft Purview compliance portal."),
        Finding("M365-COMP-002", "No DLP policies configured",
                "Compliance & Audit", "MEDIUM",
                "/security/dlp/policies", None,
                "DLP policies = 0",
                "No Data Loss Prevention policies are in place to detect sensitive data sharing.",
                "Create DLP policies for PII, financial data, and health records across Exchange, SharePoint, and Teams."),

        # Intune / Endpoint
        Finding("M365-INTUNE-001", "No device compliance policies",
                "Intune & Endpoint", "MEDIUM",
                "/deviceManagement/compliancePolicies", None,
                "Compliance policies = 0",
                "Without compliance policies, devices are not evaluated against security baselines.",
                "Create device compliance policies requiring encryption, PIN, OS version, and antivirus."),

        # Secure Score
        Finding("M365-SCORE-001", "Microsoft Secure Score below threshold",
                "Secure Score", "LOW",
                "/security/secureScores", None,
                "Current Score: 42/100 (below recommended 70)",
                "The tenant's Microsoft Secure Score indicates many improvement actions are available.",
                "Review and implement the top improvement actions in the Microsoft 365 security portal."),

        # Session & Token
        Finding("M365-TOKEN-001", "Persistent browser sessions allowed",
                "Token & Session Policies", "MEDIUM",
                "/identity/conditionalAccess/sessionControls", None,
                "PersistentBrowser = AlwaysPersistent",
                "Persistent browser sessions increase risk if a user leaves a shared device.",
                "Configure session controls in CA policies to require re-authentication on unmanaged devices."),

        # Cross-Tenant Access
        Finding("M365-XTEN-001", "Default cross-tenant inbound trust overly permissive",
                "Cross-Tenant Access", "MEDIUM",
                "/policies/crossTenantAccessPolicy/default", None,
                "InboundTrust = AllowAll (MFA + compliant device claims trusted from all tenants)",
                "Trusting MFA and device claims from all external tenants weakens your security boundary.",
                "Restrict cross-tenant inbound trust to specific partner tenants only."),

        # App & OAuth Governance
        Finding("M365-APP-001", "Users can consent to apps for themselves",
                "Admin Consent & OAuth", "HIGH",
                "/policies/authorizationPolicy", None,
                "UserConsentPolicy = AllowUserConsentForApps",
                "Users granting OAuth consent can inadvertently authorize malicious apps to access tenant data.",
                "Require admin approval for all app consent. Enable the admin consent workflow."),
    ]

    scanner.findings = synthetic_findings

    # Create output directory
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(out_dir, exist_ok=True)

    json_path = os.path.join(out_dir, "o365_sspm_report.json")
    html_path = os.path.join(out_dir, "o365_sspm_report.html")

    scanner.print_report()
    scanner.save_json(json_path)
    scanner.save_html(html_path)

    print(f"\n[+] Total findings: {len(scanner.findings)}")
    counts = scanner.summary()
    for sev, count in counts.items():
        print(f"    {sev}: {count}")

if __name__ == "__main__":
    main()
