# Multi-cloud Access Review

A read-only PowerShell tool that reviews privileged access across **Microsoft Entra ID / Azure** and **AWS** in one report, and flags the grants worth reviewing first. A smaller, self-serve version of the access governance done across large multi-cloud estates.

**[View the sample report →](https://aayyagar.github.io/multicloud-access-review/sample-report/)**

## What it flags

| Flag | Cloud | Why it matters |
|---|---|---|
| Guest / external account with a privileged role | Azure | Their security depends on another organization |
| Standing (non-JIT) privileged access | Azure | Should be PIM-eligible, not permanent |
| Stale privileged account (no recent sign-in) | Azure | Forgotten admins are quiet targets |
| Multiple high-privilege roles on one principal | Azure | Excess privilege and blast radius |
| Service principal with takeover-level permissions | Azure | App identities are often unmonitored |
| `AdministratorAccess` on a user or role | AWS | Full account control |
| No MFA on a privileged user | AWS | Password alone protects the account |
| Access key older than 90 days | AWS | Long-lived static credentials |
| Inline policies on a user | AWS | Hard to audit, often over-permissive |

Every row shows the principal, cloud, scope, access and the reason it was flagged, sorted by severity. Expected cases (like a break-glass account) are shown as low severity so the real issues stand out.

## Quick start

```powershell
# See the report with sample data from both clouds
.\Invoke-AccessReview.ps1 -Demo

# Review a cloud you are connected to
.\Invoke-AccessReview.ps1 -Cloud Azure
.\Invoke-AccessReview.ps1 -Cloud AWS
.\Invoke-AccessReview.ps1 -Cloud Both
```

Output (HTML report, JSON and CSV) is written to `.\AccessReview\`.

## Connecting to your clouds

**Azure / Entra ID** — uses Microsoft Graph with read-only scopes (`Directory.Read.All`, `RoleManagement.Read.Directory`, `AuditLog.Read.All`). A Global Reader or Security Reader account is enough.

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Connect-MgGraph -Scopes Directory.Read.All, RoleManagement.Read.Directory, AuditLog.Read.All
.\Invoke-AccessReview.ps1 -Cloud Azure
```

**AWS** — uses the AWS CLI with any read-only profile. The managed `SecurityAudit` policy is enough.

```powershell
aws configure            # or use SSO / a named profile
.\Invoke-AccessReview.ps1 -Cloud AWS
```

## Parameters

| Parameter | Description |
|---|---|
| `-Cloud` | `Azure`, `AWS`, or `Both` (default) |
| `-StaleDays` | Inactivity threshold for stale accounts (default 90) |
| `-KeyAgeDays` | AWS access-key age threshold (default 90) |
| `-OutputPath` | Output folder (default `.\AccessReview`) |
| `-Demo` | Built-in sample data, no connection |

## Why this exists

Governing identity and access across many subscriptions and accounts means answering one question constantly: *who can do the most damage, and should they still be able to?* This tool answers it on demand, in one view, read-only, so an access review is minutes rather than a day of portal-clicking.

It pairs with the [Entra ID Security Posture Checker](https://github.com/aayyagar/entra-posture-checker), which scores the tenant's configuration, while this focuses on who holds the access.

## Requirements

- PowerShell 5.1 or 7+
- Azure: `Microsoft.Graph.Authentication`
- AWS: the AWS CLI with a read-only profile

## Author

**Akhilesh Ayyagari**, Cloud Infrastructure & Identity Architect · [Portfolio](https://aayyagar.github.io) · [LinkedIn](https://www.linkedin.com/in/akhilesh-ayyagari)

## License

MIT
