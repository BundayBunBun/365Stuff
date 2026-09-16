#!/usr/bin/env python3
"""
Read-only Microsoft 365 Enterprise Application inventory.

Collects:
- Enterprise apps (service principals)
- Consented delegated and application permissions
- Approximate grant/add timestamps
- Assigned users and groups
- Whether assigned users are active and last activity
- App sign-in activity in a lookback window

Outputs:
- CSV files (apps, permissions, assignments)
- JSON summary
- Client-facing HTML dashboard
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import html
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import requests

GRAPH_V1 = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"
LOGIN_BASE = "https://login.microsoftonline.com"
PUBLIC_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

SCOPES = [
    "Application.Read.All",
    "AppRoleAssignment.ReadWrite.All",
    "DelegatedPermissionGrant.Read.All",
    "Directory.Read.All",
    "AuditLog.Read.All",
    "User.Read.All",
    "Group.Read.All",
    "offline_access",
]


@dataclass
class GraphContext:
    access_token: str
    tenant: str
    graph_base: str


class GraphClient:
    def __init__(self, context: GraphContext, timeout: int = 60) -> None:
        self.context = context
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {context.access_token}",
                "Accept": "application/json",
            }
        )

    def get(self, url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        response = self.session.get(url, params=params, timeout=self.timeout)
        if response.status_code >= 400:
            raise RuntimeError(f"Graph GET failed {response.status_code}: {response.text}")
        return response.json()

    def get_all(self, url: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        next_url = url
        next_params = params.copy() if params else None
        while next_url:
            data = self.get(next_url, params=next_params)
            value = data.get("value", [])
            if isinstance(value, list):
                items.extend(value)
            next_url = data.get("@odata.nextLink")
            next_params = None
        return items


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read-only M365 Enterprise App inventory (native Python)")
    parser.add_argument("--output-folder", default="output", help="Output folder path")
    parser.add_argument("--lookback-days", type=int, default=90, help="Activity lookback days")
    parser.add_argument("--skip-group-expansion", action="store_true", help="Do not expand users in assigned groups")
    parser.add_argument("--include-disabled-service-principals", action="store_true", help="Include disabled enterprise apps")
    parser.add_argument(
        "--tenant",
        default="organizations",
        help="Tenant ID or domain (default: organizations)",
    )
    parser.add_argument(
        "--graph-profile",
        choices=["v1.0", "beta"],
        default="beta",
        help="Graph API profile. beta improves signInActivity coverage (default: beta)",
    )
    parser.add_argument(
        "--no-browser-message",
        action="store_true",
        help="Suppress device-code prompt details (for automation logs)",
    )
    return parser.parse_args()


def device_code_auth(tenant: str, scopes: Iterable[str], no_browser_message: bool = False) -> GraphContext:
    scope_string = " ".join(scopes)
    dc_url = f"{LOGIN_BASE}/{tenant}/oauth2/v2.0/devicecode"
    token_url = f"{LOGIN_BASE}/{tenant}/oauth2/v2.0/token"

    dc_resp = requests.post(
        dc_url,
        data={
            "client_id": PUBLIC_CLIENT_ID,
            "scope": scope_string,
        },
        timeout=30,
    )
    if dc_resp.status_code >= 400:
        raise RuntimeError(f"Device code request failed {dc_resp.status_code}: {dc_resp.text}")

    dc_data = dc_resp.json()
    device_code = dc_data["device_code"]
    interval = int(dc_data.get("interval", 5))
    expires_in = int(dc_data.get("expires_in", 900))

    if not no_browser_message:
        print("\nAuthenticate to Microsoft 365:")
        print(dc_data.get("message", "Open https://microsoft.com/devicelogin and enter the code."))

    start = time.time()
    while True:
        if time.time() - start > expires_in:
            raise RuntimeError("Device code flow timed out before authentication completed.")

        token_resp = requests.post(
            token_url,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": PUBLIC_CLIENT_ID,
                "device_code": device_code,
            },
            timeout=30,
        )

        if token_resp.status_code == 200:
            token_data = token_resp.json()
            access_token = token_data["access_token"]
            break

        token_data = token_resp.json()
        err = token_data.get("error")
        if err in {"authorization_pending", "slow_down"}:
            sleep_time = interval + (5 if err == "slow_down" else 0)
            time.sleep(sleep_time)
            continue

        raise RuntimeError(f"Token request failed: {token_resp.text}")

    graph_base = GRAPH_BETA if args.graph_profile == "beta" else GRAPH_V1
    return GraphContext(access_token=access_token, tenant=tenant, graph_base=graph_base)


def to_iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def sign_in_date(sign_in_activity: Optional[Dict[str, Any]], prop_name: str) -> Optional[str]:
    if not sign_in_activity:
        return None
    return to_iso(sign_in_activity.get(prop_name))


def user_state(user: Optional[Dict[str, Any]], lookback_start: dt.datetime) -> str:
    if not user:
        return "Unknown"
    if user.get("accountEnabled") is False:
        return "Disabled"

    activity = user.get("signInActivity") or {}
    dates: List[dt.datetime] = []
    for k in ("lastSuccessfulSignInDateTime", "lastSignInDateTime"):
        val = activity.get(k)
        if not val:
            continue
        try:
            dates.append(dt.datetime.fromisoformat(val.replace("Z", "+00:00")))
        except Exception:
            continue

    if not dates:
        return "Unknown"

    latest = max(dates)
    return "ActiveInWindow" if latest >= lookback_start else "InactiveInWindow"


def graph_url(ctx: GraphContext, path: str) -> str:
    return f"{ctx.graph_base}{path}"


def build_html_report(
    app_rows: List[Dict[str, Any]],
    permission_rows: List[Dict[str, Any]],
    assignment_rows: List[Dict[str, Any]],
    tenant: str,
    generated_at: str,
    lookback_days: int,
) -> str:
    apps_json = json.dumps(app_rows).replace("</", "<\\/")
    permissions_json = json.dumps(permission_rows).replace("</", "<\\/")
    assignments_json = json.dumps(assignment_rows).replace("</", "<\\/")

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Enterprise App Security Review</title>
  <style>
    :root {{
      --ink: #1f2937;
      --muted: #5b6472;
      --paper: #fffdf8;
      --line: #e5ddd0;
      --shadow: 0 12px 30px rgba(0, 0, 0, 0.08);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", "Aptos", Tahoma, sans-serif;
      color: var(--ink);
      background:
        radial-gradient(1200px 700px at 100% -10%, #fde68a55, transparent),
        radial-gradient(900px 500px at -10% 20%, #99f6e455, transparent),
        var(--paper);
    }}
    .wrap {{ max-width: 1300px; margin: 0 auto; padding: 28px 20px 38px; }}
    .hero {{ border: 1px solid var(--line); border-radius: 18px; background: #ffffffd9; box-shadow: var(--shadow); padding: 24px; margin-bottom: 18px; }}
    h1 {{ margin: 0; font-size: clamp(1.3rem, 1.3rem + 1.1vw, 2rem); }}
    .sub {{ margin-top: 10px; color: var(--muted); font-size: .95rem; }}
    .chips {{ margin-top: 14px; display: flex; flex-wrap: wrap; gap: 8px; }}
    .chip {{ border: 1px solid var(--line); background: #fff; border-radius: 999px; font-size: .85rem; padding: 6px 11px; }}
    .kpis {{ margin: 16px 0 6px; display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }}
    .kpi {{ border: 1px solid var(--line); border-radius: 14px; padding: 14px; background: #fff; box-shadow: var(--shadow); }}
    .kpi h3 {{ margin: 0; font-size: .82rem; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; }}
    .kpi .v {{ margin-top: 8px; font-size: 1.7rem; font-weight: 700; color: #0b3f3a; }}
    .panel {{ margin-top: 16px; border: 1px solid var(--line); border-radius: 14px; background: #fff; box-shadow: var(--shadow); overflow: hidden; }}
    .panel h2 {{ margin: 0; padding: 14px 16px; font-size: 1rem; background: linear-gradient(90deg, #fef3c7aa, #ccfbf177); border-bottom: 1px solid var(--line); }}
    .controls {{ display: grid; grid-template-columns: 1fr 220px; gap: 10px; padding: 12px; border-bottom: 1px solid var(--line); background: #fcfcfb; }}
    input, select {{ width: 100%; border: 1px solid #cfd5df; border-radius: 10px; padding: 10px; font: inherit; background: #fff; }}
    .table-wrap {{ overflow: auto; }}
    table {{ border-collapse: collapse; width: 100%; min-width: 980px; font-size: .9rem; }}
    th, td {{ text-align: left; padding: 10px 11px; border-bottom: 1px solid #ece8de; vertical-align: top; }}
    thead th {{ position: sticky; top: 0; background: #faf7ef; z-index: 1; color: #434f61; font-size: .78rem; text-transform: uppercase; letter-spacing: .05em; }}
    .pill {{ display: inline-block; border-radius: 999px; padding: 4px 8px; font-size: .78rem; font-weight: 600; border: 1px solid transparent; white-space: nowrap; }}
    .ok {{ background: #dcfce7; color: #166534; border-color: #bbf7d0; }}
    .warn {{ background: #fef3c7; color: #92400e; border-color: #fde68a; }}
    .bad {{ background: #fee2e2; color: #991b1b; border-color: #fecaca; }}
    .muted {{ background: #f3f4f6; color: #4b5563; border-color: #e5e7eb; }}
    .summary {{ padding: 12px; color: var(--muted); font-size: .9rem; border-top: 1px solid var(--line); background: #fafaf8; }}
    .small {{ font-size: .82rem; color: var(--muted); }}
    @media (max-width: 900px) {{ .controls {{ grid-template-columns: 1fr; }} .wrap {{ padding: 16px 12px 30px; }} }}
  </style>
</head>
<body>
  <div class=\"wrap\">
    <section class=\"hero\">
      <h1>Enterprise Application Security Review</h1>
      <div class=\"sub\">Client-facing read-only summary from Microsoft 365 / Graph data collection.</div>
      <div class=\"chips\">
        <span class=\"chip\">Tenant: {html.escape(tenant)}</span>
        <span class=\"chip\">Generated: {html.escape(generated_at)}</span>
        <span class=\"chip\">Activity lookback: {lookback_days} days</span>
        <span class=\"chip\">Mode: Read-only Graph GET/list</span>
      </div>
      <div class=\"kpis\" id=\"kpis\"></div>
    </section>
    <section class=\"panel\">
      <h2>Application Inventory</h2>
      <div class=\"controls\">
        <input id=\"search\" type=\"search\" placeholder=\"Search by app name, publisher, AppId...\" />
        <select id=\"activityFilter\">
          <option value=\"all\">All activity states</option>
          <option value=\"has\">Has app activity in window</option>
          <option value=\"none\">No app activity in window</option>
        </select>
      </div>
      <div class=\"table-wrap\">
        <table>
          <thead><tr><th>App</th><th>Consented</th><th>Permissions</th><th>Assignments</th><th>User Health</th><th>App Activity</th><th>Added</th></tr></thead>
          <tbody id=\"appRows\"></tbody>
        </table>
      </div>
      <div class=\"summary\" id=\"summary\"></div>
    </section>
  </div>
  <script>
    const apps = {apps_json};
    const permissions = {permissions_json};
    const assignments = {assignments_json};
    const appRowsEl = document.getElementById('appRows');
    const summaryEl = document.getElementById('summary');
    const kpisEl = document.getElementById('kpis');
    const searchEl = document.getElementById('search');
    const activityFilterEl = document.getElementById('activityFilter');
    const appPermissionCounts = new Map();
    const appAssignmentUserStats = new Map();
    for (const p of permissions) {{
      const key = p.AppObjectId || '';
      if (!appPermissionCounts.has(key)) appPermissionCounts.set(key, {{ delegated: 0, application: 0 }});
      const bucket = appPermissionCounts.get(key);
      if (p.PermissionType === 'Delegated') bucket.delegated += 1;
      if (p.PermissionType === 'Application') bucket.application += 1;
    }}
    for (const a of assignments) {{
      const key = a.AppObjectId || '';
      if (!appAssignmentUserStats.has(key)) {{
        appAssignmentUserStats.set(key, {{ users: new Set(), active: new Set(), inactive: new Set(), disabled: new Set(), unknown: new Set() }});
      }}
      if (a.AssignedPrincipalType !== 'User') continue;
      const id = a.AssignedPrincipalId || `${{a.AssignedPrincipalDisplayName}}|${{a.AssignedUserPrincipalName}}`;
      const stat = appAssignmentUserStats.get(key);
      stat.users.add(id);
      switch (a.UserActivityState) {{
        case 'ActiveInWindow': stat.active.add(id); break;
        case 'InactiveInWindow': stat.inactive.add(id); break;
        case 'Disabled': stat.disabled.add(id); break;
        default: stat.unknown.add(id); break;
      }}
    }}
    function fmt(dt) {{
      if (!dt) return '-';
      const d = new Date(dt);
      if (Number.isNaN(d.getTime())) return dt;
      return d.toLocaleString();
    }}
    function badge(type, text) {{ return `<span class=\"pill ${{type}}\">${{text}}</span>`; }}
    function renderKpis() {{
      const consented = apps.filter(a => a.IsConsented).length;
      const withActivity = apps.filter(a => a.HasAppSignInActivityInWindow).length;
      const noActivity = apps.length - withActivity;
      const assignedUsers = new Set();
      const disabledUsers = new Set();
      for (const a of assignments) {{
        if (a.AssignedPrincipalType !== 'User') continue;
        const id = a.AssignedPrincipalId || `${{a.AssignedPrincipalDisplayName}}|${{a.AssignedUserPrincipalName}}`;
        assignedUsers.add(id);
        if (a.AccountEnabled === false) disabledUsers.add(id);
      }}
      const blocks = [
        ['Total Apps', apps.length],
        ['Consented Apps', consented],
        ['Apps With Activity', withActivity],
        ['Apps Without Activity', noActivity],
        ['Distinct Assigned Users', assignedUsers.size],
        ['Assigned Users Disabled', disabledUsers.size]
      ];
      kpisEl.innerHTML = blocks.map(([label, value]) => `<article class=\"kpi\"><h3>${{label}}</h3><div class=\"v\">${{value}}</div></article>`).join('');
    }}
    function appFilter(app) {{
      const q = searchEl.value.trim().toLowerCase();
      const mode = activityFilterEl.value;
      if (mode === 'has' && !app.HasAppSignInActivityInWindow) return false;
      if (mode === 'none' && app.HasAppSignInActivityInWindow) return false;
      if (!q) return true;
      const text = [app.AppDisplayName, app.PublisherName, app.AppId, app.ServicePrincipalType].filter(Boolean).join(' ').toLowerCase();
      return text.includes(q);
    }}
    function renderTable() {{
      const filtered = apps.filter(appFilter).sort((a, b) => (a.AppDisplayName || '').localeCompare(b.AppDisplayName || ''));
      const rows = filtered.map(app => {{
        const key = app.AppObjectId || '';
        const perm = appPermissionCounts.get(key) || {{ delegated: 0, application: 0 }};
        const stats = appAssignmentUserStats.get(key) || {{ users: new Set(), active: new Set(), inactive: new Set(), disabled: new Set(), unknown: new Set() }};
        const consentPill = app.IsConsented ? badge('ok', 'Yes') : badge('warn', 'No');
        const activityPill = app.HasAppSignInActivityInWindow ? badge('ok', 'Recorded') : badge('warn', 'None in window');
        return `<tr>
          <td><strong>${{app.AppDisplayName || '-'}}</strong><br /><span class=\"small\">${{app.AppId || '-'}}</span></td>
          <td>${{consentPill}}</td>
          <td>${{badge('muted', `Delegated: ${{perm.delegated}}`)}} ${{badge('muted', `Application: ${{perm.application}}`)}}</td>
          <td>${{badge('muted', `Users: ${{stats.users.size}}`)}} ${{badge('muted', `Groups: ${{app.DirectAssignedGroups || 0}}`)}}</td>
          <td>${{badge('ok', `Active: ${{stats.active.size}}`)}} ${{badge('warn', `Inactive: ${{stats.inactive.size}}`)}} ${{badge('bad', `Disabled: ${{stats.disabled.size}}`)}} ${{badge('muted', `Unknown: ${{stats.unknown.size}}`)}}</td>
          <td>${{activityPill}}<br /><span class=\"small\">${{fmt(app.LastAppSignInDateTimeInWindow)}}</span></td>
          <td>${{fmt(app.ServicePrincipalCreatedDateTime)}}</td>
        </tr>`;
      }}).join('');
      appRowsEl.innerHTML = rows || '<tr><td colspan=\"7\">No applications match the current filters.</td></tr>';
      summaryEl.textContent = `Showing ${{filtered.length}} of ${{apps.length}} applications.`;
    }}
    renderKpis();
    renderTable();
    searchEl.addEventListener('input', renderTable);
    activityFilterEl.addEventListener('change', renderTable);
  </script>
</body>
</html>
"""


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k) for k in fieldnames})


def get_user(client: GraphClient, cache: Dict[str, Optional[Dict[str, Any]]], user_id: str) -> Optional[Dict[str, Any]]:
    if not user_id:
        return None
    if user_id in cache:
        return cache[user_id]
    try:
        data = client.get(
            graph_url(client.context, f"/users/{user_id}"),
            params={"$select": "id,displayName,userPrincipalName,accountEnabled,signInActivity"},
        )
    except Exception:
        data = None
    cache[user_id] = data
    return data


def get_group(client: GraphClient, cache: Dict[str, Optional[Dict[str, Any]]], group_id: str) -> Optional[Dict[str, Any]]:
    if not group_id:
        return None
    if group_id in cache:
        return cache[group_id]
    try:
        data = client.get(
            graph_url(client.context, f"/groups/{group_id}"),
            params={"$select": "id,displayName,mail,mailNickname,securityEnabled"},
        )
    except Exception:
        data = None
    cache[group_id] = data
    return data


def get_resource_sp(client: GraphClient, cache: Dict[str, Optional[Dict[str, Any]]], sp_id: str) -> Optional[Dict[str, Any]]:
    if not sp_id:
        return None
    if sp_id in cache:
        return cache[sp_id]
    try:
        data = client.get(
            graph_url(client.context, f"/servicePrincipals/{sp_id}"),
            params={"$select": "id,appId,displayName,appRoles,oauth2PermissionScopes"},
        )
    except Exception:
        data = None
    cache[sp_id] = data
    return data


def resolve_scope_display(resource_sp: Optional[Dict[str, Any]], scope_value: str) -> Optional[str]:
    if not resource_sp or not scope_value:
        return None
    for scope in resource_sp.get("oauth2PermissionScopes", []) or []:
        if scope.get("value") == scope_value:
            return scope.get("adminConsentDisplayName") or scope.get("userConsentDisplayName") or scope.get("value")
    return None


def resolve_app_role(resource_sp: Optional[Dict[str, Any]], role_id: str) -> Optional[str]:
    if not resource_sp or not role_id:
        return None
    for role in resource_sp.get("appRoles", []) or []:
        if str(role.get("id")) == str(role_id):
            return role.get("value") or role.get("displayName")
    return None


def get_latest_app_signin(client: GraphClient, app_id: str, lookback_start: dt.datetime) -> Dict[str, Any]:
    if not app_id:
        return {"HasActivityInWindow": False, "LastActivityDateTime": None, "Error": None}
    start_iso = lookback_start.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        data = client.get(
            graph_url(client.context, "/auditLogs/signIns"),
            params={
                "$filter": f"appId eq '{app_id}' and createdDateTime ge {start_iso}",
                "$orderby": "createdDateTime desc",
                "$top": "1",
            },
        )
        vals = data.get("value", [])
        last = vals[0].get("createdDateTime") if vals else None
        return {"HasActivityInWindow": bool(last), "LastActivityDateTime": last, "Error": None}
    except Exception as exc:
        return {"HasActivityInWindow": False, "LastActivityDateTime": None, "Error": str(exc)}


def main() -> int:
    output = Path(args.output_folder).resolve()
    output.mkdir(parents=True, exist_ok=True)

    context = device_code_auth(args.tenant, SCOPES, args.no_browser_message)
    context.graph_base = GRAPH_BETA if args.graph_profile == "beta" else GRAPH_V1
    client = GraphClient(context)

    print(f"Connected tenant selector: {args.tenant}")
    print(f"Graph profile: {args.graph_profile}")
    print("Read-only mode: Graph GET/list only")

    lookback_days = abs(args.lookback_days)
    lookback_start = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=lookback_days)
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")

    sp_select = "id,appId,displayName,createdDateTime,accountEnabled,publisherName,servicePrincipalType"
    sps = client.get_all(
        graph_url(context, "/servicePrincipals"),
        params={"$select": sp_select, "$top": "999"},
    )

    if not args.include_disabled_service_principals:
        sps = [sp for sp in sps if sp.get("accountEnabled") is not False]

    user_cache: Dict[str, Optional[Dict[str, Any]]] = {}
    group_cache: Dict[str, Optional[Dict[str, Any]]] = {}
    resource_sp_cache: Dict[str, Optional[Dict[str, Any]]] = {}

    app_rows: List[Dict[str, Any]] = []
    permission_rows: List[Dict[str, Any]] = []
    assignment_rows: List[Dict[str, Any]] = []

    total = len(sps)
    for idx, sp in enumerate(sps, start=1):
        app_name = sp.get("displayName") or "<unnamed>"
        print(f"[{idx}/{total}] Processing: {app_name}")

        sp_id = sp.get("id", "")
        app_id = sp.get("appId", "")

        try:
            delegated_grants = client.get_all(
                graph_url(context, "/oauth2PermissionGrants"),
                params={
                    "$filter": f"clientId eq '{sp_id}'",
                    "$select": "id,clientId,consentType,principalId,resourceId,scope,createdDateTime",
                    "$top": "999",
                },
            )
        except Exception as exc:
            print(f"Warning: delegated grant read failed for {app_name}: {exc}")
            delegated_grants = []

        try:
            application_grants = client.get_all(
                graph_url(context, f"/servicePrincipals/{sp_id}/appRoleAssignments"),
                params={"$select": "id,appRoleId,resourceId,createdDateTime", "$top": "999"},
            )
        except Exception as exc:
            print(f"Warning: application grant read failed for {app_name}: {exc}")
            application_grants = []

        try:
            principal_assignments = client.get_all(
                graph_url(context, f"/servicePrincipals/{sp_id}/appRoleAssignedTo"),
                params={"$select": "id,appRoleId,principalId,principalDisplayName,principalType,createdDateTime", "$top": "999"},
            )
        except Exception as exc:
            print(f"Warning: assignment read failed for {app_name}: {exc}")
            principal_assignments = []

        for grant in delegated_grants:
            resource_sp = get_resource_sp(client, resource_sp_cache, grant.get("resourceId", ""))
            raw_scope = grant.get("scope") or ""
            scopes = [s for s in raw_scope.split(" ") if s.strip()]

            if not scopes:
                permission_rows.append(
                    {
                        "AppDisplayName": sp.get("displayName"),
                        "AppObjectId": sp_id,
                        "AppId": app_id,
                        "PermissionType": "Delegated",
                        "PermissionValue": None,
                        "PermissionDisplayName": None,
                        "ResourceDisplayName": resource_sp.get("displayName") if resource_sp else None,
                        "ResourceAppId": resource_sp.get("appId") if resource_sp else None,
                        "ConsentType": grant.get("consentType"),
                        "GrantedToPrincipalId": grant.get("principalId"),
                        "GrantedToPrincipal": None,
                        "GrantedDateTime": to_iso(grant.get("createdDateTime")),
                    }
                )
                continue

            grant_user_label: Optional[str] = None
            principal_id = grant.get("principalId")
            if principal_id:
                grant_user = get_user(client, user_cache, principal_id)
                if grant_user:
                    grant_user_label = grant_user.get("userPrincipalName") or grant_user.get("displayName")

            for scope in scopes:
                permission_rows.append(
                    {
                        "AppDisplayName": sp.get("displayName"),
                        "AppObjectId": sp_id,
                        "AppId": app_id,
                        "PermissionType": "Delegated",
                        "PermissionValue": scope,
                        "PermissionDisplayName": resolve_scope_display(resource_sp, scope),
                        "ResourceDisplayName": resource_sp.get("displayName") if resource_sp else None,
                        "ResourceAppId": resource_sp.get("appId") if resource_sp else None,
                        "ConsentType": grant.get("consentType"),
                        "GrantedToPrincipalId": principal_id,
                        "GrantedToPrincipal": grant_user_label,
                        "GrantedDateTime": to_iso(grant.get("createdDateTime")),
                    }
                )

        for grant in application_grants:
            resource_sp = get_resource_sp(client, resource_sp_cache, grant.get("resourceId", ""))
            role_val = resolve_app_role(resource_sp, grant.get("appRoleId"))
            permission_rows.append(
                {
                    "AppDisplayName": sp.get("displayName"),
                    "AppObjectId": sp_id,
                    "AppId": app_id,
                    "PermissionType": "Application",
                    "PermissionValue": role_val,
                    "PermissionDisplayName": role_val,
                    "ResourceDisplayName": resource_sp.get("displayName") if resource_sp else None,
                    "ResourceAppId": resource_sp.get("appId") if resource_sp else None,
                    "ConsentType": "AllPrincipals",
                    "GrantedToPrincipalId": None,
                    "GrantedToPrincipal": None,
                    "GrantedDateTime": to_iso(grant.get("createdDateTime")),
                }
            )

        direct_assigned_users = 0
        direct_assigned_groups = 0
        expanded_group_members = 0

        for assignment in principal_assignments:
            principal_type = assignment.get("principalType")
            app_role_name = resolve_app_role(sp, assignment.get("appRoleId"))

            if principal_type == "User":
                direct_assigned_users += 1
                user = get_user(client, user_cache, assignment.get("principalId", ""))
                activity = user.get("signInActivity") if user else {}
                assignment_rows.append(
                    {
                        "AppDisplayName": sp.get("displayName"),
                        "AppObjectId": sp_id,
                        "AppId": app_id,
                        "AssignmentSource": "Direct",
                        "AssignedPrincipalType": "User",
                        "AssignedPrincipalDisplayName": user.get("displayName") if user else assignment.get("principalDisplayName"),
                        "AssignedPrincipalId": assignment.get("principalId"),
                        "AssignedUserPrincipalName": user.get("userPrincipalName") if user else None,
                        "AssignmentAppRole": app_role_name,
                        "AssignmentCreatedDateTime": to_iso(assignment.get("createdDateTime")),
                        "AccountEnabled": user.get("accountEnabled") if user else None,
                        "LastSignInDateTime": sign_in_date(activity, "lastSignInDateTime"),
                        "LastSuccessfulSignInDateTime": sign_in_date(activity, "lastSuccessfulSignInDateTime"),
                        "UserActivityState": user_state(user, lookback_start),
                        "ViaGroupId": None,
                        "ViaGroupDisplayName": None,
                    }
                )
                continue

            if principal_type == "Group":
                direct_assigned_groups += 1
                group = get_group(client, group_cache, assignment.get("principalId", ""))

                assignment_rows.append(
                    {
                        "AppDisplayName": sp.get("displayName"),
                        "AppObjectId": sp_id,
                        "AppId": app_id,
                        "AssignmentSource": "Direct",
                        "AssignedPrincipalType": "Group",
                        "AssignedPrincipalDisplayName": group.get("displayName") if group else assignment.get("principalDisplayName"),
                        "AssignedPrincipalId": assignment.get("principalId"),
                        "AssignedUserPrincipalName": None,
                        "AssignmentAppRole": app_role_name,
                        "AssignmentCreatedDateTime": to_iso(assignment.get("createdDateTime")),
                        "AccountEnabled": None,
                        "LastSignInDateTime": None,
                        "LastSuccessfulSignInDateTime": None,
                        "UserActivityState": None,
                        "ViaGroupId": None,
                        "ViaGroupDisplayName": None,
                    }
                )

                if not args.skip_group_expansion:
                    try:
                        members = client.get_all(
                            graph_url(context, f"/groups/{assignment.get('principalId')}/transitiveMembers/microsoft.graph.user"),
                            params={"$select": "id", "$top": "999"},
                        )
                    except Exception as exc:
                        print(
                            "Warning: group member expansion failed for "
                            f"{assignment.get('principalDisplayName')}: {exc}"
                        )
                        members = []

                    for member in members:
                        m_user = get_user(client, user_cache, member.get("id", ""))
                        if not m_user:
                            continue
                        expanded_group_members += 1
                        m_activity = m_user.get("signInActivity") or {}
                        assignment_rows.append(
                            {
                                "AppDisplayName": sp.get("displayName"),
                                "AppObjectId": sp_id,
                                "AppId": app_id,
                                "AssignmentSource": "GroupMemberExpansion",
                                "AssignedPrincipalType": "User",
                                "AssignedPrincipalDisplayName": m_user.get("displayName"),
                                "AssignedPrincipalId": m_user.get("id"),
                                "AssignedUserPrincipalName": m_user.get("userPrincipalName"),
                                "AssignmentAppRole": app_role_name,
                                "AssignmentCreatedDateTime": to_iso(assignment.get("createdDateTime")),
                                "AccountEnabled": m_user.get("accountEnabled"),
                                "LastSignInDateTime": sign_in_date(m_activity, "lastSignInDateTime"),
                                "LastSuccessfulSignInDateTime": sign_in_date(m_activity, "lastSuccessfulSignInDateTime"),
                                "UserActivityState": user_state(m_user, lookback_start),
                                "ViaGroupId": assignment.get("principalId"),
                                "ViaGroupDisplayName": group.get("displayName") if group else assignment.get("principalDisplayName"),
                            }
                        )
                continue

            assignment_rows.append(
                {
                    "AppDisplayName": sp.get("displayName"),
                    "AppObjectId": sp_id,
                    "AppId": app_id,
                    "AssignmentSource": "Direct",
                    "AssignedPrincipalType": principal_type,
                    "AssignedPrincipalDisplayName": assignment.get("principalDisplayName"),
                    "AssignedPrincipalId": assignment.get("principalId"),
                    "AssignedUserPrincipalName": None,
                    "AssignmentAppRole": app_role_name,
                    "AssignmentCreatedDateTime": to_iso(assignment.get("createdDateTime")),
                    "AccountEnabled": None,
                    "LastSignInDateTime": None,
                    "LastSuccessfulSignInDateTime": None,
                    "UserActivityState": None,
                    "ViaGroupId": None,
                    "ViaGroupDisplayName": None,
                }
            )

        app_signin = get_latest_app_signin(client, app_id, lookback_start)

        app_perms = [p for p in permission_rows if p.get("AppObjectId") == sp_id]
        delegated_count = sum(1 for p in app_perms if p.get("PermissionType") == "Delegated")
        application_count = sum(1 for p in app_perms if p.get("PermissionType") == "Application")

        app_rows.append(
            {
                "AppDisplayName": sp.get("displayName"),
                "AppObjectId": sp_id,
                "AppId": app_id,
                "PublisherName": sp.get("publisherName"),
                "ServicePrincipalType": sp.get("servicePrincipalType"),
                "ServicePrincipalCreatedDateTime": to_iso(sp.get("createdDateTime")),
                "AccountEnabled": sp.get("accountEnabled"),
                "IsConsented": (delegated_count + application_count) > 0,
                "DelegatedPermissionCount": delegated_count,
                "ApplicationPermissionCount": application_count,
                "DirectAssignedUsers": direct_assigned_users,
                "DirectAssignedGroups": direct_assigned_groups,
                "ExpandedAssignedUsersViaGroups": expanded_group_members,
                "HasAppSignInActivityInWindow": app_signin["HasActivityInWindow"],
                "LastAppSignInDateTimeInWindow": app_signin["LastActivityDateTime"],
                "AppSignInLookupError": app_signin["Error"],
            }
        )

    app_rows.sort(key=lambda x: (x.get("AppDisplayName") or "").lower())
    permission_rows.sort(key=lambda x: (
        (x.get("AppDisplayName") or "").lower(),
        x.get("PermissionType") or "",
        x.get("ResourceDisplayName") or "",
        x.get("PermissionValue") or "",
    ))
    assignment_rows.sort(key=lambda x: (
        (x.get("AppDisplayName") or "").lower(),
        x.get("AssignmentSource") or "",
        x.get("AssignedPrincipalType") or "",
        x.get("AssignedPrincipalDisplayName") or "",
    ))

    app_csv = output / f"EnterpriseApps_{timestamp}.csv"
    perm_csv = output / f"EnterpriseAppPermissions_{timestamp}.csv"
    assign_csv = output / f"EnterpriseAppAssignments_{timestamp}.csv"
    summary_json = output / f"EnterpriseAppInventory_{timestamp}.json"
    html_path = output / f"EnterpriseAppReview_{timestamp}.html"

    app_fields = [
        "AppDisplayName",
        "AppObjectId",
        "AppId",
        "PublisherName",
        "ServicePrincipalType",
        "ServicePrincipalCreatedDateTime",
        "AccountEnabled",
        "IsConsented",
        "DelegatedPermissionCount",
        "ApplicationPermissionCount",
        "DirectAssignedUsers",
        "DirectAssignedGroups",
        "ExpandedAssignedUsersViaGroups",
        "HasAppSignInActivityInWindow",
        "LastAppSignInDateTimeInWindow",
        "AppSignInLookupError",
    ]

    perm_fields = [
        "AppDisplayName",
        "AppObjectId",
        "AppId",
        "PermissionType",
        "PermissionValue",
        "PermissionDisplayName",
        "ResourceDisplayName",
        "ResourceAppId",
        "ConsentType",
        "GrantedToPrincipalId",
        "GrantedToPrincipal",
        "GrantedDateTime",
    ]

    assign_fields = [
        "AppDisplayName",
        "AppObjectId",
        "AppId",
        "AssignmentSource",
        "AssignedPrincipalType",
        "AssignedPrincipalDisplayName",
        "AssignedPrincipalId",
        "AssignedUserPrincipalName",
        "AssignmentAppRole",
        "AssignmentCreatedDateTime",
        "AccountEnabled",
        "LastSignInDateTime",
        "LastSuccessfulSignInDateTime",
        "UserActivityState",
        "ViaGroupId",
        "ViaGroupDisplayName",
    ]

    write_csv(app_csv, app_rows, app_fields)
    write_csv(perm_csv, permission_rows, perm_fields)
    write_csv(assign_csv, assignment_rows, assign_fields)

    generated = utc_now_iso()
    summary = {
        "GeneratedAtUtc": generated,
        "TenantSelector": args.tenant,
        "GraphProfile": args.graph_profile,
        "LookbackDays": lookback_days,
        "IncludeDisabledServicePrincipals": bool(args.include_disabled_service_principals),
        "GroupMemberExpansionEnabled": not bool(args.skip_group_expansion),
        "Reports": {
            "Apps": str(app_csv),
            "Permissions": str(perm_csv),
            "Assignments": str(assign_csv),
            "Html": str(html_path),
        },
        "AppCount": len(app_rows),
        "PermissionRowCount": len(permission_rows),
        "AssignmentRowCount": len(assignment_rows),
    }
    summary_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    html_report = build_html_report(app_rows, permission_rows, assignment_rows, args.tenant, generated, lookback_days)
    html_path.write_text(html_report, encoding="utf-8")

    print("\nReport complete.")
    print(f"Apps:        {app_csv}")
    print(f"Permissions: {perm_csv}")
    print(f"Assignments: {assign_csv}")
    print(f"HTML:        {html_path}")
    print(f"Summary:     {summary_json}")
    print("\nThis script is read-only: it only uses GET/list operations against Microsoft Graph.")

    return 0


if __name__ == "__main__":
    args = parse_args()
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Interrupted by user.")
        sys.exit(130)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
