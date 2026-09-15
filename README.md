# Microsoft 365 Enterprise App Inventory (Read-Only)

This workspace contains a read-only PowerShell script to inventory Enterprise Applications in a Microsoft 365 tenant.

## Script

- `Get-M365EnterpriseAppInventory.ps1`

## What it collects

- Enterprise application list (service principals)
- Whether each app has consented permissions
- Delegated permissions and application permissions
- Approximate grant creation timestamps (when available from Graph objects)
- Direct user/group assignments to each app
- User status for assigned users:
  - Account enabled/disabled
  - Last sign-in timestamp (if available)
  - Last successful sign-in timestamp (if available)
  - Active/inactive in a configurable lookback window
- App sign-in activity presence in a configurable lookback window
  - Latest observed sign-in timestamp in window
- A polished, client-facing HTML dashboard for easy review

## Read-only guarantee

The script only uses Microsoft Graph read/list operations.
It does not create, update, or delete any tenant object.

## Prerequisites

1. PowerShell 7+ recommended.
2. Microsoft Graph PowerShell modules:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

3. Ability to consent/use these Graph delegated scopes:

- `Application.Read.All`
- `AppRoleAssignment.Read.All`
- `Directory.Read.All`
- `AuditLog.Read.All`
- `User.Read.All`
- `Group.Read.All`

## Usage

Basic run:

```powershell
.\Get-M365EnterpriseAppInventory.ps1 -OutputFolder .\output
```

Use beta profile (helpful in some tenants for richer sign-in fields):

```powershell
.\Get-M365EnterpriseAppInventory.ps1 -OutputFolder .\output -UseBetaProfile
```

Skip expansion of users inside assigned groups (faster for very large tenants):

```powershell
.\Get-M365EnterpriseAppInventory.ps1 -OutputFolder .\output -SkipGroupMemberExpansion
```

Change activity lookback window (default 90 days):

```powershell
.\Get-M365EnterpriseAppInventory.ps1 -OutputFolder .\output -SignInLookbackDays 180
```

Include disabled enterprise app service principals:

```powershell
.\Get-M365EnterpriseAppInventory.ps1 -OutputFolder .\output -IncludeDisabledServicePrincipals
```

## Output files

The script writes timestamped reports:

- `EnterpriseApps_yyyyMMdd_HHmmss.csv`
- `EnterpriseAppPermissions_yyyyMMdd_HHmmss.csv`
- `EnterpriseAppAssignments_yyyyMMdd_HHmmss.csv`
- `EnterpriseAppReview_yyyyMMdd_HHmmss.html`
- `EnterpriseAppInventory_yyyyMMdd_HHmmss.json`

## Client-facing HTML report

- Open the generated `EnterpriseAppReview_*.html` file in any modern browser.
- Includes:
  - Executive KPI cards
  - Search and activity filtering
  - Per-app view of consent, permissions, assignments, user status, and app activity
- The HTML report is generated from the same read-only data collected by the script.

## Notes

- Some "when added" or activity fields can be null depending on tenant data availability and role permissions.
- User sign-in fields may require additional directory roles in your tenant even when scopes are granted.
- App activity is determined from sign-in logs in the specified lookback window.
