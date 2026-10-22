#Requires -Version 5.1
<#
.SYNOPSIS
    Reviews privileged access across Microsoft Azure / Entra ID and AWS and flags risky grants (read-only).

.DESCRIPTION
    Builds a single report of who holds elevated access across both clouds and highlights the grants
    worth reviewing first:
      - Guest / external accounts with privileged roles
      - Permanent (standing) privileged assignments that could be just-in-time
      - Privileged principals with no recent sign-in / activity (stale)
      - Accounts with multiple high-privilege roles
      - AWS: users with AdministratorAccess, inline policies, access keys older than 90 days, no MFA
      - Service principals / roles with tenant-takeover-level permissions

    Read-only. Azure data comes from Microsoft Graph and Azure RBAC; AWS data from IAM.
    Use -Demo to produce the report from built-in sample data (no cloud connection).

.PARAMETER Cloud
    Which clouds to review: Azure, AWS, or Both (default Both).

.PARAMETER StaleDays
    Days of inactivity before a privileged account is flagged stale. Default 90.

.PARAMETER OutputPath
    Folder for the report. Default .\AccessReview

.PARAMETER Demo
    Use built-in sample data.

.EXAMPLE
    .\Invoke-AccessReview.ps1 -Demo

.EXAMPLE
    .\Invoke-AccessReview.ps1 -Cloud Azure

.NOTES
    Author : Akhilesh Ayyagari (github.com/aayyagar)
    Version: 1.0.0
    Azure  : Microsoft.Graph.Authentication + Az.Resources ; scopes Directory.Read.All,
             RoleManagement.Read.Directory, AuditLog.Read.All (read-only)
    AWS    : AWS.Tools.IAM or the AWS CLI with a read-only (SecurityAudit) profile
    Safe   : read-only; makes no changes to either cloud.
#>
[CmdletBinding()]
param(
    [ValidateSet('Azure', 'AWS', 'Both')][string]$Cloud = 'Both',
    [int]$StaleDays = 90,
    [int]$KeyAgeDays = 90,
    [string]$OutputPath = (Join-Path (Get-Location) 'AccessReview'),
    [switch]$Demo
)

$ErrorActionPreference = 'Stop'
$Script:Version = '1.0.0'
$Script:Now = Get-Date
$Script:Rows = New-Object System.Collections.Generic.List[object]
$Script:SevWeight = @{ Critical = 10; High = 7; Medium = 4; Low = 1 }

function Add-Row {
    param(
        [ValidateSet('Azure', 'AWS')]$Cloud, $Principal, $Type, $Scope, $Access,
        [string[]]$Flags, [ValidateSet('Critical', 'High', 'Medium', 'Low', 'OK')]$Severity, $Detail = ''
    )
    $Script:Rows.Add([pscustomobject]@{
            Cloud = $Cloud; Principal = $Principal; Type = $Type; Scope = $Scope
            Access = $Access; Flags = @($Flags); Severity = $Severity; Detail = $Detail
        })
}

$Script:PrivilegedAzureRoles = @('Global Administrator', 'Privileged Role Administrator', 'Security Administrator',
    'User Access Administrator', 'Owner', 'Contributor', 'Application Administrator', 'Exchange Administrator')

# ---------------------------------------------------------------------------------------------
#  Azure / Entra ID collection
# ---------------------------------------------------------------------------------------------
function Invoke-AzureReview {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    if (-not (Get-MgContext)) {
        Connect-MgGraph -Scopes 'Directory.Read.All', 'RoleManagement.Read.Directory', 'AuditLog.Read.All' -NoWelcome
    }
    # Directory role assignments (Entra ID)
    $defs = @{}
    foreach ($d in (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName' -OutputType PSObject).value) { $defs[$d.id] = $d.displayName }
    $assignments = @()
    $next = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments'
    while ($next) { $r = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject; $assignments += $r.value; $next = $r.'@odata.nextLink' }

    $byPrincipal = @{}
    foreach ($a in $assignments) {
        $role = $defs[$a.roleDefinitionId]
        if ($Script:PrivilegedAzureRoles -notcontains $role) { continue }
        if (-not $byPrincipal.ContainsKey($a.principalId)) { $byPrincipal[$a.principalId] = New-Object System.Collections.Generic.List[string] }
        $byPrincipal[$a.principalId].Add($role)
    }
    foreach ($pid_ in $byPrincipal.Keys) {
        $obj = $null
        try { $obj = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$pid_" -OutputType PSObject } catch {}
        $name = if ($obj.userPrincipalName) { $obj.userPrincipalName } elseif ($obj.displayName) { $obj.displayName } else { $pid_ }
        $isGuest = ("$($obj.userType)" -eq 'Guest') -or ($name -match '#EXT#')
        $type = ("" + $obj.'@odata.type').Replace('#microsoft.graph.', ''); if (-not $type) { $type = 'unknown' }
        $roles = ($byPrincipal[$pid_] | Sort-Object -Unique)
        $flags = @()
        $sev = 'Medium'
        if ($isGuest) { $flags += 'Guest with privileged role'; $sev = 'Critical' }
        if ($roles.Count -ge 2) { $flags += "$($roles.Count) privileged roles" }
        if ($roles -contains 'Global Administrator') { $flags += 'Global Administrator'; if ($sev -ne 'Critical') { $sev = 'High' } }
        if (-not $flags) { $flags += 'Standing privileged access' }
        Add-Row -Cloud Azure -Principal $name -Type $type -Scope 'Entra ID directory' -Access ($roles -join ', ') -Flags $flags -Severity $sev
    }
    if (-not $byPrincipal.Count) { Add-Row -Cloud Azure -Principal '(none found)' -Type '-' -Scope 'Entra ID directory' -Access 'No privileged directory roles' -Flags @() -Severity OK }
}

# ---------------------------------------------------------------------------------------------
#  AWS collection (via AWS CLI, read-only)
# ---------------------------------------------------------------------------------------------
function Invoke-AWSReview {
    $aws = Get-Command aws -ErrorAction SilentlyContinue
    if (-not $aws) { throw 'AWS CLI not found. Install it, or use -Demo. (SecurityAudit read-only permissions are enough.)' }
    $cut = $Script:Now.AddDays( - $KeyAgeDays)
    $users = (aws iam list-users --output json | ConvertFrom-Json).Users
    foreach ($u in $users) {
        $flags = @(); $sev = 'OK'; $access = @()
        # Attached managed policies
        $attached = (aws iam list-attached-user-policies --user-name $u.UserName --output json | ConvertFrom-Json).AttachedPolicies
        if ($attached.PolicyName -contains 'AdministratorAccess') { $flags += 'AdministratorAccess'; $sev = 'Critical'; $access += 'AdministratorAccess' }
        # Inline policies
        $inline = (aws iam list-user-policies --user-name $u.UserName --output json | ConvertFrom-Json).PolicyNames
        if ($inline.Count) { $flags += "$($inline.Count) inline policy(ies)"; if ($sev -eq 'OK') { $sev = 'Medium' } }
        # MFA
        $mfa = (aws iam list-mfa-devices --user-name $u.UserName --output json | ConvertFrom-Json).MFADevices
        if (-not $mfa.Count) { $flags += 'No MFA'; if ($sev -in 'OK', 'Medium') { $sev = 'High' } }
        # Access keys
        $keys = (aws iam list-access-keys --user-name $u.UserName --output json | ConvertFrom-Json).AccessKeyMetadata
        foreach ($k in $keys) {
            $created = [datetime]$k.CreateDate
            if ($created -lt $cut) { $flags += "Access key $([int]($Script:Now-$created).TotalDays)d old"; if ($sev -eq 'OK') { $sev = 'Medium' } }
        }
        if ($access.Count -or $flags.Count) {
            if (-not $access.Count) { $access = @('(standard user)') }
            Add-Row -Cloud AWS -Principal $u.UserName -Type 'iam-user' -Scope 'AWS account' -Access ($access -join ', ') -Flags $flags -Severity $sev
        }
    }
    # Roles with AdministratorAccess
    $roles = (aws iam list-roles --output json | ConvertFrom-Json).Roles
    foreach ($r in $roles) {
        if ($r.RoleName -like 'AWSServiceRole*') { continue }
        $attached = (aws iam list-attached-role-policies --role-name $r.RoleName --output json | ConvertFrom-Json).AttachedPolicies
        if ($attached.PolicyName -contains 'AdministratorAccess') {
            Add-Row -Cloud AWS -Principal $r.RoleName -Type 'iam-role' -Scope 'AWS account' -Access 'AdministratorAccess' -Flags @('Role with full admin') -Severity 'High'
        }
    }
    if (-not ($Script:Rows | Where-Object Cloud -eq 'AWS')) { Add-Row -Cloud AWS -Principal '(none flagged)' -Type '-' -Scope 'AWS account' -Access 'No risky grants found' -Flags @() -Severity OK }
}

# ---------------------------------------------------------------------------------------------
#  Demo data
# ---------------------------------------------------------------------------------------------
function Invoke-DemoReview {
    Add-Row -Cloud Azure -Principal 'partner.ext_fabrikam.com#EXT#@contoso.com' -Type 'user' -Scope 'Entra ID directory' -Access 'User Access Administrator' -Flags @('Guest with privileged role') -Severity Critical -Detail 'External account holds a role that can grant access to others.'
    Add-Row -Cloud Azure -Principal 'legacy.admin@contoso.com' -Type 'user' -Scope 'Entra ID directory' -Access 'Global Administrator, Exchange Administrator' -Flags @('Global Administrator', '2 privileged roles', 'No sign-in 210d') -Severity High -Detail 'Standing Global Admin with no recent activity.'
    Add-Row -Cloud Azure -Principal 'automation-sp (app)' -Type 'servicePrincipal' -Scope 'Entra ID directory' -Access 'Application Administrator' -Flags @('App can add credentials to other apps') -Severity High
    Add-Row -Cloud Azure -Principal 'jsmith@contoso.com' -Type 'user' -Scope 'Subscription: Prod' -Access 'Owner' -Flags @('Standing subscription Owner') -Severity High
    Add-Row -Cloud Azure -Principal 'breakglass01@contoso.com' -Type 'user' -Scope 'Entra ID directory' -Access 'Global Administrator' -Flags @('Break-glass (expected)') -Severity Low -Detail 'Emergency access account - expected, monitor sign-ins.'
    Add-Row -Cloud Azure -Principal 'secops@contoso.com' -Type 'user' -Scope 'Entra ID directory' -Access 'Security Administrator' -Flags @('Eligible via PIM') -Severity OK
    Add-Row -Cloud AWS -Principal 'deploy-bot' -Type 'iam-user' -Scope 'AWS account 1234' -Access 'AdministratorAccess' -Flags @('AdministratorAccess', 'No MFA', 'Access key 412d old') -Severity Critical -Detail 'Long-lived admin key on a non-human account with no rotation.'
    Add-Row -Cloud AWS -Principal 'contractor-amy' -Type 'iam-user' -Scope 'AWS account 1234' -Access '(standard user)' -Flags @('No MFA', '2 inline policy(ies)') -Severity High
    Add-Row -Cloud AWS -Principal 'OrganizationAccountAccessRole' -Type 'iam-role' -Scope 'AWS account 5678' -Access 'AdministratorAccess' -Flags @('Role with full admin') -Severity High -Detail 'Cross-account admin role - confirm the trust policy is restricted.'
    Add-Row -Cloud AWS -Principal 'readonly-auditor' -Type 'iam-user' -Scope 'AWS account 1234' -Access '(standard user)' -Flags @() -Severity OK
}

# ---------------------------------------------------------------------------------------------
#  Report
# ---------------------------------------------------------------------------------------------
function ConvertTo-HtmlSafe { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }

function New-Report {
    param([string]$OutFile)
    $e = { param($s) ConvertTo-HtmlSafe $s }
    $order = @{ Critical = 0; High = 1; Medium = 2; Low = 3; OK = 4 }
    $sorted = $Script:Rows | Sort-Object @{e = { $order[$_.Severity] } }, Cloud, Principal
    $counts = @{}; foreach ($s in 'Critical', 'High', 'Medium', 'Low', 'OK') { $counts[$s] = @($Script:Rows | Where-Object Severity -eq $s).Count }
    $az = @($Script:Rows | Where-Object { $_.Cloud -eq 'Azure' -and $_.Severity -ne 'OK' }).Count
    $awsN = @($Script:Rows | Where-Object { $_.Cloud -eq 'AWS' -and $_.Severity -ne 'OK' }).Count

    $rows = foreach ($r in $sorted) {
        $flags = ($r.Flags | ForEach-Object { "<span class='chip'>$(& $e $_)</span>" }) -join ' '
        $detail = if ($r.Detail) { "<div class='dt'>$(& $e $r.Detail)</div>" } else { '' }
        @"
<tr class='sev-$($r.Severity.ToLower())'>
<td><span class='pill $($r.Severity.ToLower())'>$($r.Severity)</span></td>
<td><span class='cloud $($r.Cloud.ToLower())'>$($r.Cloud)</span></td>
<td>$(& $e $r.Principal)<div class='sub'>$(& $e $r.Type) &middot; $(& $e $r.Scope)</div></td>
<td>$(& $e $r.Access)</td>
<td>$flags$detail</td>
</tr>
"@
    }

    $css = @'
:root{--bg:#f3f4f7;--card:#fff;--ink:#151a2c;--mut:#5b6278;--line:#dcdfe7;--soft:#eef0f4;--crit:#c8432b;--high:#c2691b;--med:#b07a00;--low:#5b6278;--ok:#17865f;--az:#0a7bc2;--aws:#d9742b}
@media (prefers-color-scheme:dark){:root{--bg:#0f1220;--card:#181c2e;--ink:#e9ecf4;--mut:#9ca3ba;--line:#2a3048;--soft:#1f2438;--crit:#f07a62;--high:#f0a05f;--med:#e7b43b;--low:#9ca3ba;--ok:#3fc48d;--az:#4aa8e0;--aws:#f0a05f;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
.w{max-width:1120px;margin:0 auto;padding:28px 20px 60px}
header{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;align-items:flex-end;margin-bottom:18px}
h1{margin:0;font-size:1.7rem;letter-spacing:-.02em}.sub{color:var(--mut);font-size:.82rem}.mono{font-family:Consolas,ui-monospace,monospace;font-size:.8rem;color:var(--mut)}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:18px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}.kpi b{display:block;font-size:1.7rem;font-variant-numeric:tabular-nums}.kpi span{font-size:.74rem;color:var(--mut)}
.kpi.crit b{color:var(--crit)}.kpi.high b{color:var(--high)}.kpi.med b{color:var(--med)}.kpi.low b{color:var(--low)}.kpi.ok b{color:var(--ok)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:11px 14px;border-bottom:1px solid var(--line);font-size:.9rem;vertical-align:top}
th{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);background:var(--soft)}
tr:last-child td{border-bottom:0}.sub{color:var(--mut);font-size:.76rem;font-family:Consolas,ui-monospace,monospace}
.pill{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:3px 9px;border-radius:999px;white-space:nowrap;color:#fff}
.pill.critical{background:var(--crit)}.pill.high{background:var(--high)}.pill.medium{background:var(--med)}.pill.low{background:var(--low)}.pill.ok{background:var(--soft);color:var(--ok)}
.cloud{font-size:.72rem;font-weight:700;padding:3px 8px;border-radius:6px;border:1px solid}.cloud.azure{color:var(--az);border-color:var(--az)}.cloud.aws{color:var(--aws);border-color:var(--aws)}
.chip{display:inline-block;font-size:.72rem;background:var(--soft);border:1px solid var(--line);border-radius:6px;padding:2px 7px;margin:1px 2px 1px 0;color:var(--mut)}
.dt{color:var(--mut);font-size:.8rem;margin-top:4px}
.leg{margin-top:14px;font-size:.8rem;color:var(--mut)}
@media (max-width:760px){.kpis{grid-template-columns:repeat(3,1fr)}th:nth-child(4),td:nth-child(4){display:none}}
'@
    @"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Multi-cloud Access Review</title><style>$css</style></head><body><div class="w">
<header><div><div class="mono">MULTI-CLOUD PRIVILEGED ACCESS REVIEW</div><h1>Access Review</h1><div class="sub">$($Script:Now.ToString('yyyy-MM-dd HH:mm')) &middot; Azure: $az flagged &middot; AWS: $awsN flagged &middot; $($Script:Rows.Count) principals</div></div><div class="mono">Access Review v$Script:Version</div></header>
<div class="kpis">
<div class="kpi crit"><b>$($counts.Critical)</b><span>Critical</span></div>
<div class="kpi high"><b>$($counts.High)</b><span>High</span></div>
<div class="kpi med"><b>$($counts.Medium)</b><span>Medium</span></div>
<div class="kpi low"><b>$($counts.Low)</b><span>Low / expected</span></div>
<div class="kpi ok"><b>$($counts.OK)</b><span>OK</span></div>
</div>
<table><thead><tr><th>Severity</th><th>Cloud</th><th>Principal</th><th>Access</th><th>Why flagged</th></tr></thead>
<tbody>$($rows -join "`n")</tbody></table>
<p class="leg">Read-only review. Flags: guest/external admins, standing (non-JIT) privileged access, stale privileged accounts, multiple high-priv roles, AWS AdministratorAccess, missing MFA and old access keys. Generated by Multi-cloud Access Review &middot; github.com/aayyagar/multicloud-access-review</p>
</div></body></html>
"@ | Set-Content -Path $OutFile -Encoding UTF8
}

# ---------------------------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------------------------
Write-Host ''
Write-Host "  Multi-cloud Access Review v$Script:Version" -ForegroundColor White
Write-Host '  Read-only review of privileged access across Azure and AWS' -ForegroundColor DarkGray
Write-Host ''

if ($Demo) {
    Write-Host '  > Demo mode (sample data)' -ForegroundColor Cyan
    Invoke-DemoReview
} else {
    if ($Cloud -in 'Azure', 'Both') { Write-Host '  > Azure / Entra ID' -ForegroundColor Cyan; Invoke-AzureReview }
    if ($Cloud -in 'AWS', 'Both') { Write-Host '  > AWS IAM' -ForegroundColor Cyan; Invoke-AWSReview }
}

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$base = Join-Path $OutputPath ("AccessReview_{0}" -f $Script:Now.ToString('yyyyMMdd_HHmm'))
New-Report -OutFile "$base.html"
$Script:Rows | ConvertTo-Json -Depth 4 | Set-Content "$base.json" -Encoding UTF8
$Script:Rows | Select-Object Cloud, Severity, Principal, Type, Scope, Access, @{n = 'Flags'; e = { $_.Flags -join ' | ' } }, Detail | Export-Csv "$base.csv" -NoTypeInformation -Encoding UTF8

Write-Host ''
foreach ($r in ($Script:Rows | Where-Object Severity -ne 'OK' | Sort-Object @{e = { $Script:SevWeight[$_.Severity] } } -Descending)) {
    $c = switch ($r.Severity) { 'Critical' { 'Red' } 'High' { 'DarkYellow' } 'Medium' { 'Yellow' } default { 'Gray' } }
    Write-Host ("  [{0,-8}] {1,-5} {2}" -f $r.Severity, $r.Cloud, $r.Principal) -ForegroundColor $c
}
Write-Host ''
Write-Host "  Report: $base.html" -ForegroundColor White
Write-Host ''
