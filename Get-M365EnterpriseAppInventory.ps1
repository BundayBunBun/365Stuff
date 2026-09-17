[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputFolder = ".",

    [Parameter(Mandatory = $false)]
    [int]$SignInLookbackDays = 90,

    [Parameter(Mandatory = $false)]
    [switch]$SkipGroupMemberExpansion,

    [Parameter(Mandatory = $false)]
    [switch]$UseBetaProfile,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabledServicePrincipals,

    [Parameter(Mandatory = $false)]
    [switch]$UseDeviceCode,

    [Parameter(Mandatory = $false)]
    [switch]$UseBrowserAuth
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Applications',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Identity.SignIns'
)

$requiredScopes = @(
    'Application.Read.All',
    'AppRoleAssignment.ReadWrite.All',
    'DelegatedPermissionGrant.Read.All',
    'Directory.Read.All',
    'AuditLog.Read.All',
    'User.Read.All',
    'Group.Read.All'
)

function Ensure-MgModules {
    foreach ($moduleName in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            throw "Missing module '$moduleName'. Install with: Install-Module $moduleName -Scope CurrentUser"
        }
    }
}

function To-NullableDateTimeString {
    param([object]$Value)

    if ($null -eq $Value) {
        return $null
    }

    try {
        return ([DateTimeOffset]$Value).UtcDateTime.ToString('o')
    }
    catch {
        return $Value.ToString()
    }
}

function Add-MissingGraphProperty {
    param(
        [string]$EntityType,
        [string]$PropertyName,
        [string]$EntityId
    )

    $safeEntityType = if ([string]::IsNullOrWhiteSpace($EntityType)) { 'UnknownEntity' } else { $EntityType }
    $safePropertyName = if ([string]::IsNullOrWhiteSpace($PropertyName)) { 'UnknownProperty' } else { $PropertyName }
    $key = "$safeEntityType|$safePropertyName"

    if (-not $script:missingGraphPropertyCounts.ContainsKey($key)) {
        $script:missingGraphPropertyCounts[$key] = [pscustomobject]@{
            EntityType = $safeEntityType
            PropertyName = $safePropertyName
            MissingCount = 0
            SampleEntityIds = [System.Collections.Generic.List[string]]::new()
        }
    }

    $entry = $script:missingGraphPropertyCounts[$key]
    $entry.MissingCount++

    if (-not [string]::IsNullOrWhiteSpace($EntityId) -and $entry.SampleEntityIds.Count -lt 5 -and -not $entry.SampleEntityIds.Contains($EntityId)) {
        $entry.SampleEntityIds.Add($EntityId)
    }
}

function Get-SafeGraphProperty {
    param(
        [object]$InputObject,
        [string]$PropertyName,
        [string]$EntityType,
        [string]$EntityId,
        [object]$DefaultValue = $null,
        [switch]$TrackMissing
    )

    if ($null -eq $InputObject) {
        if ($TrackMissing) {
            Add-MissingGraphProperty -EntityType $EntityType -PropertyName $PropertyName -EntityId $EntityId
        }
        return $DefaultValue
    }

    if ($InputObject.PSObject.Properties.Name -contains $PropertyName) {
        return $InputObject.$PropertyName
    }

    if ($InputObject.PSObject.Properties.Name -contains 'AdditionalProperties') {
        $additional = $InputObject.AdditionalProperties
        if ($additional -and $additional.ContainsKey($PropertyName)) {
            return $additional[$PropertyName]
        }
    }

    if ($TrackMissing) {
        Add-MissingGraphProperty -EntityType $EntityType -PropertyName $PropertyName -EntityId $EntityId
    }

    return $DefaultValue
}

function Get-SignInActivityDate {
    param(
        [object]$SignInActivity,
        [string]$PropertyName
    )

    if ($null -eq $SignInActivity) {
        return $null
    }

    if ($SignInActivity.PSObject.Properties.Name -contains $PropertyName) {
        return To-NullableDateTimeString -Value $SignInActivity.$PropertyName
    }

    if ($SignInActivity.PSObject.Properties.Name -contains 'AdditionalProperties') {
        $additional = $SignInActivity.AdditionalProperties
        if ($additional -and $additional.ContainsKey($PropertyName)) {
            return To-NullableDateTimeString -Value $additional[$PropertyName]
        }
    }

    return $null
}

function Get-ResourceSpFromCache {
    param([string]$ResourceId)

    if ([string]::IsNullOrWhiteSpace($ResourceId)) {
        return $null
    }

    if ($script:resourceSpCache.ContainsKey($ResourceId)) {
        return $script:resourceSpCache[$ResourceId]
    }

    try {
        $resourceSp = Get-MgServicePrincipal -ServicePrincipalId $ResourceId -Property "id,appId,displayName,appRoles,oauth2PermissionScopes"
    }
    catch {
        $resourceSp = $null
    }

    $script:resourceSpCache[$ResourceId] = $resourceSp
    return $resourceSp
}

function Resolve-DelegatedPermissionDisplay {
    param(
        [object]$ResourceSp,
        [string]$ScopeValue
    )

    if ($null -eq $ResourceSp -or [string]::IsNullOrWhiteSpace($ScopeValue)) {
        return $null
    }

    $scopeDefinition = $ResourceSp.Oauth2PermissionScopes | Where-Object { $_.Value -eq $ScopeValue } | Select-Object -First 1
    if ($null -eq $scopeDefinition) {
        return $null
    }

    if (-not [string]::IsNullOrWhiteSpace($scopeDefinition.AdminConsentDisplayName)) {
        return $scopeDefinition.AdminConsentDisplayName
    }

    if (-not [string]::IsNullOrWhiteSpace($scopeDefinition.UserConsentDisplayName)) {
        return $scopeDefinition.UserConsentDisplayName
    }

    return $scopeDefinition.Value
}

function Resolve-AppRoleValue {
    param(
        [object]$ResourceSp,
        [string]$AppRoleId
    )

    if ($null -eq $ResourceSp -or [string]::IsNullOrWhiteSpace($AppRoleId)) {
        return $null
    }

    $appRole = $ResourceSp.AppRoles | Where-Object { $_.Id -eq $AppRoleId } | Select-Object -First 1
    if ($null -eq $appRole) {
        return $null
    }

    if (-not [string]::IsNullOrWhiteSpace($appRole.Value)) {
        return $appRole.Value
    }

    return $appRole.DisplayName
}

function Get-UserFromCache {
    param([string]$UserId)

    if ([string]::IsNullOrWhiteSpace($UserId)) {
        return $null
    }

    if ($script:userCache.ContainsKey($UserId)) {
        return $script:userCache[$UserId]
    }

    try {
        $user = Get-MgUser -UserId $UserId -Property "id,displayName,userPrincipalName,accountEnabled,signInActivity"
    }
    catch {
        $user = $null
    }

    $script:userCache[$UserId] = $user
    return $user
}

function Get-GroupFromCache {
    param([string]$GroupId)

    if ([string]::IsNullOrWhiteSpace($GroupId)) {
        return $null
    }

    if ($script:groupCache.ContainsKey($GroupId)) {
        return $script:groupCache[$GroupId]
    }

    try {
        $group = Get-MgGroup -GroupId $GroupId -Property "id,displayName,mail,mailNickname,securityEnabled"
    }
    catch {
        $group = $null
    }

    $script:groupCache[$GroupId] = $group
    return $group
}

function Test-UserActiveInWindow {
    param(
        [object]$User,
        [DateTimeOffset]$LookbackStart
    )

    if ($null -eq $User) {
        return 'Unknown'
    }

    if ($false -eq $User.AccountEnabled) {
        return 'Disabled'
    }

    $lastSignIn = Get-SignInActivityDate -SignInActivity $User.SignInActivity -PropertyName 'lastSignInDateTime'
    $lastInteractive = Get-SignInActivityDate -SignInActivity $User.SignInActivity -PropertyName 'lastSuccessfulSignInDateTime'

    $effective = @($lastInteractive, $lastSignIn) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { [DateTimeOffset]$_ } |
        Sort-Object -Descending |
        Select-Object -First 1

    if ($null -eq $effective) {
        return 'Unknown'
    }

    if ($effective -ge $LookbackStart) {
        return 'ActiveInWindow'
    }

    return 'InactiveInWindow'
}

function Get-AppLatestSignIn {
    param(
        [string]$AppId,
        [DateTimeOffset]$LookbackStart
    )

    if ([string]::IsNullOrWhiteSpace($AppId)) {
        return [pscustomobject]@{
            HasActivityInWindow = $false
            LastActivityDateTime = $null
            Error = $null
        }
    }

    $isoLookback = $LookbackStart.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $uri = "/auditLogs/signIns?`$filter=appId eq '$AppId' and createdDateTime ge $isoLookback&`$orderby=createdDateTime desc&`$top=1"

    try {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        $latest = $null

        if ($response.value -and $response.value.Count -gt 0) {
            $latest = To-NullableDateTimeString -Value $response.value[0].createdDateTime
        }

        return [pscustomobject]@{
            HasActivityInWindow = [bool]($null -ne $latest)
            LastActivityDateTime = $latest
            Error = $null
        }
    }
    catch {
        return [pscustomobject]@{
            HasActivityInWindow = $false
            LastActivityDateTime = $null
            Error = $_.Exception.Message
        }
    }
}

function Get-AppSignInActivityMap {
    param([DateTimeOffset]$LookbackStart)

    $map = @{}
    $isoLookback = $LookbackStart.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $uri = "/auditLogs/signIns?`$filter=createdDateTime ge $isoLookback&`$select=appId,createdDateTime&`$orderby=createdDateTime desc&`$top=1000"

    try {
        while (-not [string]::IsNullOrWhiteSpace($uri)) {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri
            $items = @($response.value)

            foreach ($entry in $items) {
                $appId = $entry.appId
                if ([string]::IsNullOrWhiteSpace($appId)) {
                    continue
                }

                if (-not $map.ContainsKey($appId)) {
                    $map[$appId] = To-NullableDateTimeString -Value $entry.createdDateTime
                }
            }

            if ($response.PSObject.Properties.Name -contains '@odata.nextLink') {
                $uri = $response.'@odata.nextLink'
            }
            else {
                $uri = $null
            }
        }

        return [pscustomobject]@{
            Success = $true
            Error = $null
            Map = $map
        }
    }
    catch {
        return [pscustomobject]@{
            Success = $false
            Error = $_.Exception.Message
            Map = @{}
        }
    }
}

function ConvertTo-SafeJsonForHtmlScript {
        param([object]$Value)

        $json = $Value | ConvertTo-Json -Depth 10 -Compress
        return $json -replace '</', '<\/'
}

function New-EnterpriseAppHtmlReport {
        param(
                [Parameter(Mandatory = $true)]
                [object[]]$AppRows,

                [Parameter(Mandatory = $true)]
                [object[]]$PermissionRows,

                [Parameter(Mandatory = $true)]
                [object[]]$AssignmentRows,

                [Parameter(Mandatory = $true)]
                [string]$OutputPath,

                [Parameter(Mandatory = $true)]
                [string]$TenantId,

                [Parameter(Mandatory = $true)]
                [string]$GeneratedAtUtc,

                [Parameter(Mandatory = $true)]
                [int]$LookbackDays
        )

        $appsJson = ConvertTo-SafeJsonForHtmlScript -Value $AppRows
        $permissionsJson = ConvertTo-SafeJsonForHtmlScript -Value $PermissionRows
        $assignmentsJson = ConvertTo-SafeJsonForHtmlScript -Value $AssignmentRows
        $tenantIdEncoded = [System.Net.WebUtility]::HtmlEncode($TenantId)
        $generatedEncoded = [System.Net.WebUtility]::HtmlEncode($GeneratedAtUtc)

        $template = @'
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Enterprise App Security Review</title>
    <style>
        :root {
            --ink: #1f2937;
            --muted: #5b6472;
            --paper: #fffdf8;
            --accent: #0f766e;
            --accent-soft: #ccfbf1;
            --warn: #b45309;
            --danger: #b91c1c;
            --line: #e5ddd0;
            --card: #ffffffcc;
            --shadow: 0 12px 30px rgba(0, 0, 0, 0.08);
        }

        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: "Segoe UI", "Aptos", Tahoma, sans-serif;
            color: var(--ink);
            background:
                radial-gradient(1200px 700px at 100% -10%, #fde68a55, transparent),
                radial-gradient(900px 500px at -10% 20%, #99f6e455, transparent),
                var(--paper);
        }

        .wrap {
            max-width: 1300px;
            margin: 0 auto;
            padding: 28px 20px 38px;
        }

        .hero {
            border: 1px solid var(--line);
            border-radius: 18px;
            background: linear-gradient(125deg, #ffffffd9, #f7f6f2d9);
            box-shadow: var(--shadow);
            padding: 24px;
            margin-bottom: 18px;
        }

        h1 {
            margin: 0;
            font-size: clamp(1.3rem, 1.3rem + 1.1vw, 2rem);
            letter-spacing: 0.2px;
        }

        .sub {
            margin-top: 10px;
            color: var(--muted);
            font-size: 0.95rem;
        }

        .chips {
            margin-top: 14px;
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }

        .chip {
            border: 1px solid var(--line);
            background: #fff;
            color: #384252;
            border-radius: 999px;
            font-size: 0.85rem;
            padding: 6px 11px;
        }

        .kpis {
            margin: 16px 0 6px;
            display: grid;
            gap: 12px;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        }

        .kpi {
            border: 1px solid var(--line);
            border-radius: 14px;
            padding: 14px;
            background: var(--card);
            box-shadow: var(--shadow);
            backdrop-filter: blur(1px);
            animation: rise 500ms ease both;
        }

        .kpi h3 {
            margin: 0;
            font-size: 0.82rem;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }

        .kpi .v {
            margin-top: 8px;
            font-size: 1.7rem;
            font-weight: 700;
            color: #0b3f3a;
        }

        .panel {
            margin-top: 16px;
            border: 1px solid var(--line);
            border-radius: 14px;
            background: #fff;
            box-shadow: var(--shadow);
            overflow: hidden;
            animation: rise 700ms ease both;
        }

        .panel h2 {
            margin: 0;
            padding: 14px 16px;
            font-size: 1rem;
            background: linear-gradient(90deg, #fef3c7aa, #ccfbf177);
            border-bottom: 1px solid var(--line);
        }

        .controls {
            display: grid;
            grid-template-columns: 1fr 220px;
            gap: 10px;
            padding: 12px;
            border-bottom: 1px solid var(--line);
            background: #fcfcfb;
        }

        input, select {
            width: 100%;
            border: 1px solid #cfd5df;
            border-radius: 10px;
            padding: 10px;
            font: inherit;
            background: #fff;
        }

        .table-wrap { overflow: auto; }

        table {
            border-collapse: collapse;
            width: 100%;
            min-width: 1300px;
            font-size: 0.9rem;
        }

        th, td {
            text-align: left;
            padding: 10px 11px;
            border-bottom: 1px solid #ece8de;
            vertical-align: top;
        }

        thead th {
            position: sticky;
            top: 0;
            background: #faf7ef;
            z-index: 1;
            color: #434f61;
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .pill {
            display: inline-block;
            border-radius: 999px;
            padding: 4px 8px;
            font-size: 0.78rem;
            font-weight: 600;
            border: 1px solid transparent;
            white-space: nowrap;
        }

        .ok { background: #dcfce7; color: #166534; border-color: #bbf7d0; }
        .warn { background: #fef3c7; color: #92400e; border-color: #fde68a; }
        .bad { background: #fee2e2; color: #991b1b; border-color: #fecaca; }
        .muted { background: #f3f4f6; color: #4b5563; border-color: #e5e7eb; }

        .summary {
            padding: 12px;
            color: var(--muted);
            font-size: 0.9rem;
            border-top: 1px solid var(--line);
            background: #fafaf8;
        }

        .small { font-size: 0.82rem; color: var(--muted); }

        .listbox {
            margin-top: 8px;
            max-height: 120px;
            overflow: auto;
            border: 1px solid #ece8de;
            border-radius: 8px;
            padding: 6px;
            background: #fcfcfb;
        }

        .listitem {
            font-size: 0.8rem;
            color: #3f4957;
            line-height: 1.35;
            padding: 2px 0;
            border-bottom: 1px dashed #eee7da;
        }

        .listitem:last-child {
            border-bottom: none;
        }

        @keyframes rise {
            from { opacity: 0; transform: translateY(9px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @media (max-width: 900px) {
            .controls { grid-template-columns: 1fr; }
            .wrap { padding: 16px 12px 30px; }
            .hero { padding: 16px; border-radius: 14px; }
            .panel { border-radius: 12px; }
        }
    </style>
</head>
<body>
    <div class="wrap">
        <section class="hero">
            <h1>Enterprise Application Security Review</h1>
            <div class="sub">Client-facing read-only summary from Microsoft 365 / Graph data collection.</div>
            <div class="chips">
                <span class="chip">Tenant: __TENANT_ID__</span>
                <span class="chip">Generated: __GENERATED_AT__</span>
                <span class="chip">Activity lookback: __LOOKBACK_DAYS__ days</span>
                <span class="chip">Mode: Read-only Graph GET/list</span>
            </div>
            <div class="kpis" id="kpis"></div>
        </section>

        <section class="panel">
            <h2>Application Inventory</h2>
            <div class="controls">
                <input id="search" type="search" placeholder="Search by app name, publisher, AppId..." />
                <select id="activityFilter">
                    <option value="all">All activity states</option>
                    <option value="has">Has app activity in window</option>
                    <option value="none">No app activity in window</option>
                </select>
            </div>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>App</th>
                            <th>Consented</th>
                            <th>Permissions</th>
                            <th>Assignments</th>
                            <th>User Health</th>
                            <th>App Activity</th>
                            <th>Added</th>
                        </tr>
                    </thead>
                    <tbody id="appRows"></tbody>
                </table>
            </div>
            <div class="summary" id="summary"></div>
        </section>
    </div>

    <script>
        const apps = __APPS_JSON__;
        const permissions = __PERMISSIONS_JSON__;
        const assignments = __ASSIGNMENTS_JSON__;

        const appRowsEl = document.getElementById('appRows');
        const summaryEl = document.getElementById('summary');
        const kpisEl = document.getElementById('kpis');
        const searchEl = document.getElementById('search');
        const activityFilterEl = document.getElementById('activityFilter');

        const appPermissionCounts = new Map();
        const appPermissionDetails = new Map();
        const appAssignmentUserStats = new Map();
        const appAssignedUsers = new Map();

        for (const p of permissions) {
            const key = p.AppObjectId || '';
            if (!appPermissionCounts.has(key)) {
                appPermissionCounts.set(key, { delegated: 0, application: 0 });
            }

            if (!appPermissionDetails.has(key)) {
                appPermissionDetails.set(key, new Set());
            }

            const bucket = appPermissionCounts.get(key);
            if (p.PermissionType === 'Delegated') bucket.delegated += 1;
            if (p.PermissionType === 'Application') bucket.application += 1;

            const resource = p.ResourceDisplayName || p.ResourceAppId || 'Unknown resource';
            const permValue = p.PermissionDisplayName || p.PermissionValue || 'Unknown permission';
            const detail = `${p.PermissionType || 'Unknown'} | ${resource} | ${permValue}`;
            appPermissionDetails.get(key).add(detail);
        }

        for (const a of assignments) {
            const key = a.AppObjectId || '';
            if (!appAssignmentUserStats.has(key)) {
                appAssignmentUserStats.set(key, {
                    users: new Set(),
                    active: new Set(),
                    inactive: new Set(),
                    disabled: new Set(),
                    unknown: new Set()
                });
            }

            if (!appAssignedUsers.has(key)) {
                appAssignedUsers.set(key, new Set());
            }

            if (a.AssignedPrincipalType !== 'User') continue;

            const id = a.AssignedPrincipalId || `${a.AssignedPrincipalDisplayName}|${a.AssignedUserPrincipalName}`;
            const stat = appAssignmentUserStats.get(key);
            const displayUser = a.AssignedUserPrincipalName || a.AssignedPrincipalDisplayName || id;
            stat.users.add(id);
            appAssignedUsers.get(key).add(displayUser);

            switch (a.UserActivityState) {
                case 'ActiveInWindow': stat.active.add(id); break;
                case 'InactiveInWindow': stat.inactive.add(id); break;
                case 'Disabled': stat.disabled.add(id); break;
                default: stat.unknown.add(id); break;
            }
        }

        function fmt(dt) {
            if (!dt) return '-';
            const d = new Date(dt);
            if (Number.isNaN(d.getTime())) return dt;
            return d.toLocaleString();
        }

        function badge(type, text) {
            return `<span class="pill ${type}">${text}</span>`;
        }

        function esc(value) {
            return String(value ?? '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        function toListHtml(values, emptyText) {
            if (!values || values.length === 0) {
                return `<div class="small">${esc(emptyText)}</div>`;
            }

            const topValues = values.slice(0, 20);
            const rows = topValues.map(v => `<div class="listitem">${esc(v)}</div>`).join('');
            const overflow = values.length > topValues.length
                ? `<div class="small">+${values.length - topValues.length} more</div>`
                : '';

            return `<div class="listbox">${rows}</div>${overflow}`;
        }

        function renderKpis() {
            const consented = apps.filter(a => a.IsConsented).length;
            const withActivity = apps.filter(a => a.HasAppSignInActivityInWindow).length;
            const noActivity = apps.length - withActivity;
            const assignedUsers = new Set();
            const disabledUsers = new Set();
            for (const a of assignments) {
                if (a.AssignedPrincipalType !== 'User') continue;
                const id = a.AssignedPrincipalId || `${a.AssignedPrincipalDisplayName}|${a.AssignedUserPrincipalName}`;
                assignedUsers.add(id);
                if (a.AccountEnabled === false) disabledUsers.add(id);
            }

            const blocks = [
                ['Total Apps', apps.length],
                ['Consented Apps', consented],
                ['Apps With Activity', withActivity],
                ['Apps Without Activity', noActivity],
                ['Distinct Assigned Users', assignedUsers.size],
                ['Assigned Users Disabled', disabledUsers.size]
            ];

            kpisEl.innerHTML = blocks.map(([label, value]) =>
                `<article class="kpi"><h3>${label}</h3><div class="v">${value}</div></article>`
            ).join('');
        }

        function appFilter(app) {
            const q = searchEl.value.trim().toLowerCase();
            const mode = activityFilterEl.value;

            if (mode === 'has' && !app.HasAppSignInActivityInWindow) return false;
            if (mode === 'none' && app.HasAppSignInActivityInWindow) return false;

            if (!q) return true;

            const text = [
                app.AppDisplayName,
                app.PublisherName,
                app.AppId,
                app.ServicePrincipalType
            ].filter(Boolean).join(' ').toLowerCase();

            return text.includes(q);
        }

        function renderTable() {
            const filtered = apps.filter(appFilter)
                .sort((a, b) => (a.AppDisplayName || '').localeCompare(b.AppDisplayName || ''));

            const rows = filtered.map(app => {
                const key = app.AppObjectId || '';
                const perm = appPermissionCounts.get(key) || { delegated: 0, application: 0 };
                const permDetails = Array.from(appPermissionDetails.get(key) || []).sort((a, b) => a.localeCompare(b));
                const stats = appAssignmentUserStats.get(key) || {
                    users: new Set(), active: new Set(), inactive: new Set(), disabled: new Set(), unknown: new Set()
                };
                const users = Array.from(appAssignedUsers.get(key) || []).sort((a, b) => a.localeCompare(b));

                const consentPill = app.IsConsented ? badge('ok', 'Yes') : badge('warn', 'No');
                const activityPill = app.HasAppSignInActivityInWindow ? badge('ok', 'Recorded') : badge('warn', 'None in window');

                return `<tr>
                    <td>
                        <strong>${esc(app.AppDisplayName || '-')}</strong><br />
                        <span class="small">${esc(app.AppId || '-')}</span>
                    </td>
                    <td>${consentPill}</td>
                    <td>
                        ${badge('muted', `Delegated: ${perm.delegated}`)}
                        ${badge('muted', `Application: ${perm.application}`)}
                        ${toListHtml(permDetails, 'No permissions listed')}
                    </td>
                    <td>
                        ${badge('muted', `Users: ${stats.users.size}`)}
                        ${badge('muted', `Groups: ${app.DirectAssignedGroups || 0}`)}
                        ${toListHtml(users, 'No assigned users')}
                    </td>
                    <td>
                        ${badge('ok', `Active: ${stats.active.size}`)}
                        ${badge('warn', `Inactive: ${stats.inactive.size}`)}
                        ${badge('bad', `Disabled: ${stats.disabled.size}`)}
                        ${badge('muted', `Unknown: ${stats.unknown.size}`)}
                    </td>
                    <td>
                        ${activityPill}<br />
                        <span class="small">${fmt(app.LastAppSignInDateTimeInWindow)}</span>
                    </td>
                    <td>${fmt(app.ServicePrincipalCreatedDateTime)}</td>
                </tr>`;
            }).join('');

            appRowsEl.innerHTML = rows || '<tr><td colspan="7">No applications match the current filters.</td></tr>';
            summaryEl.textContent = `Showing ${filtered.length} of ${apps.length} applications.`;
        }

        renderKpis();
        renderTable();
        searchEl.addEventListener('input', renderTable);
        activityFilterEl.addEventListener('change', renderTable);
    </script>
</body>
</html>
'@

        $html = $template.Replace('__APPS_JSON__', $appsJson)
        $html = $html.Replace('__PERMISSIONS_JSON__', $permissionsJson)
        $html = $html.Replace('__ASSIGNMENTS_JSON__', $assignmentsJson)
        $html = $html.Replace('__TENANT_ID__', $tenantIdEncoded)
        $html = $html.Replace('__GENERATED_AT__', $generatedEncoded)
        $html = $html.Replace('__LOOKBACK_DAYS__', $LookbackDays.ToString())

        Set-Content -Path $OutputPath -Value $html -Encoding UTF8
}

Ensure-MgModules

if (-not (Test-Path -Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory | Out-Null
}

if ($UseDeviceCode -and $UseBrowserAuth) {
    throw 'Use either -UseDeviceCode or -UseBrowserAuth, not both.'
}

$existingContext = Get-MgContext
$canReuseContext = $false

if ($existingContext -and $existingContext.Scopes) {
    $existingScopesLower = @($existingContext.Scopes | ForEach-Object { $_.ToLowerInvariant() })
    $missingScopes = @($requiredScopes | Where-Object { $existingScopesLower -notcontains $_.ToLowerInvariant() })
    if ($missingScopes.Count -eq 0) {
        $canReuseContext = $true
        Write-Host 'Reusing existing Microsoft Graph session.' -ForegroundColor Cyan
    }
}

if (-not $canReuseContext) {
    if ($UseDeviceCode) {
        Connect-MgGraph -Scopes $requiredScopes -UseDeviceAuthentication -ContextScope CurrentUser -NoWelcome
    }
    else {
        # Browser auth is the default flow in environments where device code is blocked.
        Connect-MgGraph -Scopes $requiredScopes -ContextScope CurrentUser -NoWelcome
    }
}

if ($UseBetaProfile) {
    Select-MgProfile -Name 'beta'
}

$context = Get-MgContext
if ($null -eq $context) {
    throw 'No active Microsoft Graph context found after Connect-MgGraph.'
}

$profileName = $null
if ($context.PSObject.Properties.Name -contains 'ProfileName') {
    $profileName = $context.ProfileName
}

if ([string]::IsNullOrWhiteSpace($profileName)) {
    try {
        $mgProfile = Get-MgProfile
        if ($mgProfile -and ($mgProfile.PSObject.Properties.Name -contains 'Name')) {
            $profileName = $mgProfile.Name
        }
    }
    catch {
        $profileName = $null
    }
}

if ([string]::IsNullOrWhiteSpace($profileName)) {
    $profileName = if ($UseBetaProfile) { 'beta' } else { 'v1.0' }
}

Write-Host "Connected to tenant: $($context.TenantId)" -ForegroundColor Cyan
Write-Host "Using profile: $profileName" -ForegroundColor Cyan
Write-Host "Scopes: $($context.Scopes -join ', ')" -ForegroundColor Cyan

$lookbackStart = [DateTimeOffset]::UtcNow.AddDays(-1 * [Math]::Abs($SignInLookbackDays))
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

$appSignInPrefetch = Get-AppSignInActivityMap -LookbackStart $lookbackStart
if (-not $appSignInPrefetch.Success) {
    Write-Warning "Could not prefetch app sign-in activity once for all apps. App activity fields will be blank. Error: $($appSignInPrefetch.Error)"
}

$spProperties = "id,appId,displayName,createdDateTime,accountEnabled,publisherName,servicePrincipalType,appOwnerOrganizationId,appRoles"
$allServicePrincipals = Get-MgServicePrincipal -All -Property $spProperties

if (-not $IncludeDisabledServicePrincipals) {
    $servicePrincipals = $allServicePrincipals | Where-Object { $_.AccountEnabled -ne $false }
}
else {
    $servicePrincipals = $allServicePrincipals
}

$script:userCache = @{}
$script:groupCache = @{}
$script:resourceSpCache = @{}
$script:missingGraphPropertyCounts = @{}

$appRows = [System.Collections.Generic.List[object]]::new()
$permissionRows = [System.Collections.Generic.List[object]]::new()
$assignmentRows = [System.Collections.Generic.List[object]]::new()

$total = ($servicePrincipals | Measure-Object).Count
$index = 0

foreach ($sp in $servicePrincipals) {
    $index++
    Write-Progress -Activity 'Processing Enterprise Applications' -Status "$index / $total" -PercentComplete (($index / [Math]::Max($total, 1)) * 100)

    $spId = [string](Get-SafeGraphProperty -InputObject $sp -PropertyName 'Id' -EntityType 'ServicePrincipal' -EntityId '' -TrackMissing)
    $spAppId = [string](Get-SafeGraphProperty -InputObject $sp -PropertyName 'AppId' -EntityType 'ServicePrincipal' -EntityId $spId -TrackMissing)
    $spDisplayName = [string](Get-SafeGraphProperty -InputObject $sp -PropertyName 'DisplayName' -EntityType 'ServicePrincipal' -EntityId $spId -DefaultValue '<Unknown App>' -TrackMissing)
    $spCreatedDateTime = Get-SafeGraphProperty -InputObject $sp -PropertyName 'CreatedDateTime' -EntityType 'ServicePrincipal' -EntityId $spId -TrackMissing
    $spAccountEnabled = Get-SafeGraphProperty -InputObject $sp -PropertyName 'AccountEnabled' -EntityType 'ServicePrincipal' -EntityId $spId -TrackMissing
    $spPublisherName = Get-SafeGraphProperty -InputObject $sp -PropertyName 'PublisherName' -EntityType 'ServicePrincipal' -EntityId $spId -TrackMissing
    $spServicePrincipalType = Get-SafeGraphProperty -InputObject $sp -PropertyName 'ServicePrincipalType' -EntityType 'ServicePrincipal' -EntityId $spId -TrackMissing

    $delegatedGrants = @()
    $applicationGrants = @()
    $principalAssignments = @()

    try {
        $delegatedGrants = Get-MgOauth2PermissionGrant -Filter "clientId eq '$spId'" -All -Property "id,clientId,consentType,principalId,resourceId,scope"
    }
    catch {
        Write-Warning "Could not read delegated permission grants for app '$spDisplayName': $($_.Exception.Message)"
    }

    try {
        $applicationGrants = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spId -All -Property "id,appRoleId,resourceId"
    }
    catch {
        Write-Warning "Could not read application permission grants for app '$spDisplayName': $($_.Exception.Message)"
    }

    try {
        $principalAssignments = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $spId -All -Property "id,appRoleId,principalId,principalDisplayName,principalType"
    }
    catch {
        Write-Warning "Could not read principal assignments for app '$spDisplayName': $($_.Exception.Message)"
    }

    foreach ($grant in $delegatedGrants) {
        $resourceSp = Get-ResourceSpFromCache -ResourceId $grant.ResourceId
        $scopes = @($grant.Scope -split ' ' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $grantCreatedDateTime = Get-SafeGraphProperty -InputObject $grant -PropertyName 'CreatedDateTime' -EntityType 'Oauth2PermissionGrant' -EntityId ([string]$grant.Id) -TrackMissing

        if ($scopes.Count -eq 0) {
            $permissionRows.Add([pscustomobject]@{
                AppDisplayName = $spDisplayName
                AppObjectId = $spId
                AppId = $spAppId
                PermissionType = 'Delegated'
                PermissionValue = $null
                PermissionDisplayName = $null
                ResourceDisplayName = if ($resourceSp) { $resourceSp.DisplayName } else { $null }
                ResourceAppId = if ($resourceSp) { $resourceSp.AppId } else { $null }
                ConsentType = $grant.ConsentType
                GrantedToPrincipalId = $grant.PrincipalId
                GrantedToPrincipal = $null
                GrantedDateTime = To-NullableDateTimeString -Value $grantCreatedDateTime
            })
            continue
        }

        foreach ($scope in $scopes) {
            $grantedTo = $null
            if (-not [string]::IsNullOrWhiteSpace($grant.PrincipalId)) {
                $consentUser = Get-UserFromCache -UserId $grant.PrincipalId
                if ($consentUser) {
                    $grantedTo = if (-not [string]::IsNullOrWhiteSpace($consentUser.UserPrincipalName)) { $consentUser.UserPrincipalName } else { $consentUser.DisplayName }
                }
            }

            $permissionRows.Add([pscustomobject]@{
                AppDisplayName = $spDisplayName
                AppObjectId = $spId
                AppId = $spAppId
                PermissionType = 'Delegated'
                PermissionValue = $scope
                PermissionDisplayName = Resolve-DelegatedPermissionDisplay -ResourceSp $resourceSp -ScopeValue $scope
                ResourceDisplayName = if ($resourceSp) { $resourceSp.DisplayName } else { $null }
                ResourceAppId = if ($resourceSp) { $resourceSp.AppId } else { $null }
                ConsentType = $grant.ConsentType
                GrantedToPrincipalId = $grant.PrincipalId
                GrantedToPrincipal = $grantedTo
                GrantedDateTime = To-NullableDateTimeString -Value $grantCreatedDateTime
            })
        }
    }

    foreach ($grant in $applicationGrants) {
        $resourceSp = Get-ResourceSpFromCache -ResourceId $grant.ResourceId
        $grantCreatedDateTime = Get-SafeGraphProperty -InputObject $grant -PropertyName 'CreatedDateTime' -EntityType 'AppRoleAssignment' -EntityId ([string]$grant.Id) -TrackMissing

        $permissionRows.Add([pscustomobject]@{
            AppDisplayName = $spDisplayName
            AppObjectId = $spId
            AppId = $spAppId
            PermissionType = 'Application'
            PermissionValue = Resolve-AppRoleValue -ResourceSp $resourceSp -AppRoleId $grant.AppRoleId
            PermissionDisplayName = Resolve-AppRoleValue -ResourceSp $resourceSp -AppRoleId $grant.AppRoleId
            ResourceDisplayName = if ($resourceSp) { $resourceSp.DisplayName } else { $null }
            ResourceAppId = if ($resourceSp) { $resourceSp.AppId } else { $null }
            ConsentType = 'AllPrincipals'
            GrantedToPrincipalId = $null
            GrantedToPrincipal = $null
            GrantedDateTime = To-NullableDateTimeString -Value $grantCreatedDateTime
        })
    }

    $directAssignedUsers = 0
    $directAssignedGroups = 0
    $expandedGroupMembers = 0

    foreach ($assignment in $principalAssignments) {
        $appRoleName = Resolve-AppRoleValue -ResourceSp $sp -AppRoleId $assignment.AppRoleId
        $assignmentCreatedDateTime = Get-SafeGraphProperty -InputObject $assignment -PropertyName 'CreatedDateTime' -EntityType 'AppRoleAssignedTo' -EntityId ([string]$assignment.Id) -TrackMissing

        if ($assignment.PrincipalType -eq 'User') {
            $directAssignedUsers++
            $user = Get-UserFromCache -UserId $assignment.PrincipalId

            $assignmentRows.Add([pscustomobject]@{
                AppDisplayName = $spDisplayName
                AppObjectId = $spId
                AppId = $spAppId
                AssignmentSource = 'Direct'
                AssignedPrincipalType = 'User'
                AssignedPrincipalDisplayName = if ($user) { $user.DisplayName } else { $assignment.PrincipalDisplayName }
                AssignedPrincipalId = $assignment.PrincipalId
                AssignedUserPrincipalName = if ($user) { $user.UserPrincipalName } else { $null }
                AssignmentAppRole = $appRoleName
                AssignmentCreatedDateTime = To-NullableDateTimeString -Value $assignmentCreatedDateTime
                AccountEnabled = if ($user) { $user.AccountEnabled } else { $null }
                LastSignInDateTime = if ($user) { Get-SignInActivityDate -SignInActivity $user.SignInActivity -PropertyName 'lastSignInDateTime' } else { $null }
                LastSuccessfulSignInDateTime = if ($user) { Get-SignInActivityDate -SignInActivity $user.SignInActivity -PropertyName 'lastSuccessfulSignInDateTime' } else { $null }
                UserActivityState = Test-UserActiveInWindow -User $user -LookbackStart $lookbackStart
                ViaGroupId = $null
                ViaGroupDisplayName = $null
            })
            continue
        }

        if ($assignment.PrincipalType -eq 'Group') {
            $directAssignedGroups++
            $group = Get-GroupFromCache -GroupId $assignment.PrincipalId

            $assignmentRows.Add([pscustomobject]@{
                AppDisplayName = $spDisplayName
                AppObjectId = $spId
                AppId = $spAppId
                AssignmentSource = 'Direct'
                AssignedPrincipalType = 'Group'
                AssignedPrincipalDisplayName = if ($group) { $group.DisplayName } else { $assignment.PrincipalDisplayName }
                AssignedPrincipalId = $assignment.PrincipalId
                AssignedUserPrincipalName = $null
                AssignmentAppRole = $appRoleName
                AssignmentCreatedDateTime = To-NullableDateTimeString -Value $assignmentCreatedDateTime
                AccountEnabled = $null
                LastSignInDateTime = $null
                LastSuccessfulSignInDateTime = $null
                UserActivityState = $null
                ViaGroupId = $null
                ViaGroupDisplayName = $null
            })

            if (-not $SkipGroupMemberExpansion) {
                try {
                    $members = Get-MgGroupTransitiveMember -GroupId $assignment.PrincipalId -All -Property "id"
                }
                catch {
                    $members = @()
                    Write-Warning "Could not expand members for group '$($assignment.PrincipalDisplayName)' in app '$spDisplayName': $($_.Exception.Message)"
                }

                foreach ($member in $members) {
                    $odataType = $member.AdditionalProperties['@odata.type']
                    if ($odataType -ne '#microsoft.graph.user') {
                        continue
                    }

                    $expandedUser = Get-UserFromCache -UserId $member.Id
                    if ($null -eq $expandedUser) {
                        continue
                    }

                    $expandedGroupMembers++

                    $assignmentRows.Add([pscustomobject]@{
                        AppDisplayName = $spDisplayName
                        AppObjectId = $spId
                        AppId = $spAppId
                        AssignmentSource = 'GroupMemberExpansion'
                        AssignedPrincipalType = 'User'
                        AssignedPrincipalDisplayName = $expandedUser.DisplayName
                        AssignedPrincipalId = $expandedUser.Id
                        AssignedUserPrincipalName = $expandedUser.UserPrincipalName
                        AssignmentAppRole = $appRoleName
                        AssignmentCreatedDateTime = To-NullableDateTimeString -Value $assignmentCreatedDateTime
                        AccountEnabled = $expandedUser.AccountEnabled
                        LastSignInDateTime = Get-SignInActivityDate -SignInActivity $expandedUser.SignInActivity -PropertyName 'lastSignInDateTime'
                        LastSuccessfulSignInDateTime = Get-SignInActivityDate -SignInActivity $expandedUser.SignInActivity -PropertyName 'lastSuccessfulSignInDateTime'
                        UserActivityState = Test-UserActiveInWindow -User $expandedUser -LookbackStart $lookbackStart
                        ViaGroupId = $assignment.PrincipalId
                        ViaGroupDisplayName = if ($group) { $group.DisplayName } else { $assignment.PrincipalDisplayName }
                    })
                }
            }

            continue
        }

        $assignmentRows.Add([pscustomobject]@{
            AppDisplayName = $spDisplayName
            AppObjectId = $spId
            AppId = $spAppId
            AssignmentSource = 'Direct'
            AssignedPrincipalType = $assignment.PrincipalType
            AssignedPrincipalDisplayName = $assignment.PrincipalDisplayName
            AssignedPrincipalId = $assignment.PrincipalId
            AssignedUserPrincipalName = $null
            AssignmentAppRole = $appRoleName
            AssignmentCreatedDateTime = To-NullableDateTimeString -Value $assignmentCreatedDateTime
            AccountEnabled = $null
            LastSignInDateTime = $null
            LastSuccessfulSignInDateTime = $null
            UserActivityState = $null
            ViaGroupId = $null
            ViaGroupDisplayName = $null
        })
    }

    $appSignIn = [pscustomobject]@{
        HasActivityInWindow = $false
        LastActivityDateTime = $null
        Error = $null
    }

    if ($appSignInPrefetch.Success) {
        if (-not [string]::IsNullOrWhiteSpace($spAppId) -and $appSignInPrefetch.Map.ContainsKey($spAppId)) {
            $appSignIn = [pscustomobject]@{
                HasActivityInWindow = $true
                LastActivityDateTime = $appSignInPrefetch.Map[$spAppId]
                Error = $null
            }
        }
    }
    else {
        $appSignIn = [pscustomobject]@{
            HasActivityInWindow = $false
            LastActivityDateTime = $null
            Error = $appSignInPrefetch.Error
        }
    }

    $appPermissionsForCurrent = $permissionRows | Where-Object { $_.AppObjectId -eq $spId }

    $delegatedCount = ($appPermissionsForCurrent | Where-Object { $_.PermissionType -eq 'Delegated' } | Measure-Object).Count
    $applicationCount = ($appPermissionsForCurrent | Where-Object { $_.PermissionType -eq 'Application' } | Measure-Object).Count

    $appRows.Add([pscustomobject]@{
        AppDisplayName = $spDisplayName
        AppObjectId = $spId
        AppId = $spAppId
        PublisherName = $spPublisherName
        ServicePrincipalType = $spServicePrincipalType
        ServicePrincipalCreatedDateTime = To-NullableDateTimeString -Value $spCreatedDateTime
        AccountEnabled = $spAccountEnabled
        IsConsented = [bool](($delegatedCount + $applicationCount) -gt 0)
        DelegatedPermissionCount = $delegatedCount
        ApplicationPermissionCount = $applicationCount
        DirectAssignedUsers = $directAssignedUsers
        DirectAssignedGroups = $directAssignedGroups
        ExpandedAssignedUsersViaGroups = $expandedGroupMembers
        HasAppSignInActivityInWindow = $appSignIn.HasActivityInWindow
        LastAppSignInDateTimeInWindow = $appSignIn.LastActivityDateTime
        AppSignInLookupError = $appSignIn.Error
    })
}

Write-Progress -Activity 'Processing Enterprise Applications' -Completed

$appReportPath = Join-Path -Path $OutputFolder -ChildPath "EnterpriseApps_$timestamp.csv"
$permissionsReportPath = Join-Path -Path $OutputFolder -ChildPath "EnterpriseAppPermissions_$timestamp.csv"
$assignmentsReportPath = Join-Path -Path $OutputFolder -ChildPath "EnterpriseAppAssignments_$timestamp.csv"
$jsonReportPath = Join-Path -Path $OutputFolder -ChildPath "EnterpriseAppInventory_$timestamp.json"
$htmlReportPath = Join-Path -Path $OutputFolder -ChildPath "EnterpriseAppReview_$timestamp.html"
$missingPropertiesReportPath = Join-Path -Path $OutputFolder -ChildPath "EnterpriseAppMissingProperties_$timestamp.csv"

$consentedAppRows = @($appRows | Where-Object { $_.IsConsented })
$consentedAppIdSet = [System.Collections.Generic.HashSet[string]]::new()
foreach ($consentedApp in $consentedAppRows) {
    if (-not [string]::IsNullOrWhiteSpace([string]$consentedApp.AppObjectId)) {
        [void]$consentedAppIdSet.Add([string]$consentedApp.AppObjectId)
    }
}

$consentedPermissionRows = @($permissionRows | Where-Object { $consentedAppIdSet.Contains([string]$_.AppObjectId) })
$consentedAssignmentRows = @($assignmentRows | Where-Object { $consentedAppIdSet.Contains([string]$_.AppObjectId) })

$assignedUsersByApp = @{}
foreach ($assignment in $consentedAssignmentRows) {
    if ($assignment.AssignedPrincipalType -ne 'User') {
        continue
    }

    $appKey = [string]$assignment.AppObjectId
    if (-not $assignedUsersByApp.ContainsKey($appKey)) {
        $assignedUsersByApp[$appKey] = [System.Collections.Generic.HashSet[string]]::new()
    }

    $userLabel = $assignment.AssignedUserPrincipalName
    if ([string]::IsNullOrWhiteSpace($userLabel)) {
        $userLabel = $assignment.AssignedPrincipalDisplayName
    }

    if (-not [string]::IsNullOrWhiteSpace($userLabel)) {
        [void]$assignedUsersByApp[$appKey].Add([string]$userLabel)
    }
}

foreach ($consentedApp in $consentedAppRows) {
    $appKey = [string]$consentedApp.AppObjectId
    $userList = @()
    if ($assignedUsersByApp.ContainsKey($appKey)) {
        $userList = @($assignedUsersByApp[$appKey] | Sort-Object)
    }

    $consentedApp | Add-Member -NotePropertyName AssignedUserCount -NotePropertyValue $userList.Count -Force
    $consentedApp | Add-Member -NotePropertyName AssignedUsers -NotePropertyValue ($userList -join '; ') -Force
}

$consentedAppRows | Sort-Object AppDisplayName | Export-Csv -NoTypeInformation -Path $appReportPath -Encoding UTF8
$consentedPermissionRows | Sort-Object AppDisplayName, PermissionType, ResourceDisplayName, PermissionValue | Export-Csv -NoTypeInformation -Path $permissionsReportPath -Encoding UTF8
$consentedAssignmentRows | Sort-Object AppDisplayName, AssignmentSource, AssignedPrincipalType, AssignedPrincipalDisplayName | Export-Csv -NoTypeInformation -Path $assignmentsReportPath -Encoding UTF8

New-EnterpriseAppHtmlReport `
    -AppRows $consentedAppRows `
    -PermissionRows $consentedPermissionRows `
    -AssignmentRows $consentedAssignmentRows `
    -OutputPath $htmlReportPath `
    -TenantId $context.TenantId `
    -GeneratedAtUtc ((Get-Date).ToUniversalTime().ToString('o')) `
    -LookbackDays ([Math]::Abs($SignInLookbackDays))

$missingPropertyRows = @(
    $script:missingGraphPropertyCounts.Values |
        Sort-Object EntityType, PropertyName |
        ForEach-Object {
            [pscustomobject]@{
                EntityType = $_.EntityType
                PropertyName = $_.PropertyName
                MissingCount = $_.MissingCount
                SampleEntityIds = ($_.SampleEntityIds -join ';')
            }
        }
)

$missingPropertyRows | Export-Csv -NoTypeInformation -Path $missingPropertiesReportPath -Encoding UTF8

[pscustomobject]@{
    GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    TenantId = $context.TenantId
    Profile = $profileName
    LookbackDays = [Math]::Abs($SignInLookbackDays)
    IncludeDisabledServicePrincipals = [bool]$IncludeDisabledServicePrincipals
    GroupMemberExpansionEnabled = [bool](-not $SkipGroupMemberExpansion)
    Reports = [pscustomobject]@{
        Apps = $appReportPath
        Permissions = $permissionsReportPath
        Assignments = $assignmentsReportPath
        Html = $htmlReportPath
        MissingProperties = $missingPropertiesReportPath
    }
    AppCount = ($consentedAppRows | Measure-Object).Count
    PermissionRowCount = ($consentedPermissionRows | Measure-Object).Count
    AssignmentRowCount = ($consentedAssignmentRows | Measure-Object).Count
    TotalDiscoveredAppCount = ($appRows | Measure-Object).Count
} | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonReportPath -Encoding utf8

Write-Host "\nReport complete." -ForegroundColor Green
Write-Host "Apps:        $appReportPath"
Write-Host "Permissions: $permissionsReportPath"
Write-Host "Assignments: $assignmentsReportPath"
Write-Host "HTML:        $htmlReportPath"
Write-Host "Missing:     $missingPropertiesReportPath"
Write-Host "Summary:     $jsonReportPath"

if (($missingPropertyRows | Measure-Object).Count -gt 0) {
    Write-Host "\nMissing properties encountered (non-fatal):" -ForegroundColor Yellow
    $missingPropertyRows | Sort-Object MissingCount -Descending | Select-Object -First 15 | Format-Table -AutoSize | Out-String | Write-Host
}
else {
    Write-Host "\nNo missing Graph properties were encountered." -ForegroundColor Green
}
Write-Host "\nThis script is read-only: it only uses GET/list operations against Microsoft Graph." -ForegroundColor Yellow
