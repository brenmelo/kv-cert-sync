#!/usr/bin/env python3
"""Inventory the Key Vaults (and optionally their certificates) of a tenant before onboarding them to the certificate factory.

Read-only. Needs `az login` (or any credential DefaultAzureCredential can use).

  vaults        Azure Resource Graph, one row per vault: permission model, purge protection, network exposure.
  --certs       Additionally lists the certificates of each vault (data plane: needs permission to list and read certificates in
                the vault, and network access to it). A vault that cannot be read is reported, never skipped silently. It also
                lists the names that certificates in more than one vault cover: one certificate issued once and copied replaces them.
  --diag        Additionally counts the diagnostic settings of each vault. The factory adds one to every destination vault
                (audit log) and Azure allows 5 per resource, so a vault that already has 5 needs one removed first.

Examples
  python scripts/inventory_vaults.py
  python scripts/inventory_vaults.py --subscription <id> --subscription <id> --certs --csv inventory.csv
  python scripts/inventory_vaults.py --vault kv-orders-prod --vault kv-web-prod --certs --diag
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import sys

import requests
from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient

ARG_URL = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
DIAG_URL = "https://management.azure.com{rid}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
DIAG_LIMIT = 5  # Azure Monitor: diagnostic settings per resource
QUERY = """
resources
| where type =~ 'microsoft.keyvault/vaults'
| project id, name, subscriptionId, resourceGroup, location,
          rbac = tostring(properties.enableRbacAuthorization),
          purge = tostring(properties.enablePurgeProtection),
          softDelete = tostring(properties.enableSoftDelete),
          publicAccess = tostring(properties.publicNetworkAccess),
          firewall = tostring(properties.networkAcls.defaultAction),
          privateEndpoints = array_length(properties.privateEndpointConnections),
          uri = tostring(properties.vaultUri)
| order by subscriptionId asc, name asc
"""
SYNC_TAGS = ("kvsync", "kvrenew", "kvsync-origin")


def vault_rows(cred, subscriptions):
    token = cred.get_token("https://management.azure.com/.default").token
    body = {"query": QUERY, "options": {"$top": 1000}}
    if subscriptions:
        body["subscriptions"] = subscriptions
    rows, skip = [], 0
    while True:
        body["options"]["$skip"] = skip
        r = requests.post(ARG_URL, json=body, headers={"Authorization": f"Bearer {token}"}, timeout=60)
        r.raise_for_status()
        j = r.json()
        rows += j["data"]
        skip += len(j["data"])
        if not j["data"] or skip >= j["totalRecords"]:
            return rows


def model(v):
    return "RBAC" if str(v["rbac"]).lower() == "true" else "access policy"


def normalise(v):
    """Resource Graph returns '' / null for properties a vault never set."""
    v["purge"] = "on" if str(v["purge"]).lower() == "true" else "off"
    v["privateEndpoints"] = v["privateEndpoints"] or 0
    v["firewall"] = (v["firewall"] or "none").lower()
    v["publicAccess"] = (v["publicAccess"] or "Enabled").lower()
    return v


def diag_count(cred, vault):
    """Number of diagnostic settings on the vault, or None when it cannot be read (the caller prints '?')."""
    try:
        token = cred.get_token("https://management.azure.com/.default").token
        r = requests.get(DIAG_URL.format(rid=vault["id"]), headers={"Authorization": f"Bearer {token}"}, timeout=60)
        r.raise_for_status()
        return len(r.json().get("value", []))
    except Exception:  # noqa: BLE001  a vault we cannot read is shown as '?', never as zero
        return None


def vault_hint(v):
    hints = []
    if model(v) != "RBAC":
        hints.append("access policies: the factory's role assignment is ignored here. Add an access policy (get, list, import) for the sync identity by hand, or migrate the vault to RBAC as a separate change")
    if v["publicAccess"] == "disabled" or v["firewall"] == "deny":
        hints.append("network-restricted: the sync function needs a route and DNS to this vault (private endpoint / VNet integration)")
    if v["purge"] != "on":
        hints.append("purge protection is off")
    if isinstance(v.get("diagSettings"), int) and v["diagSettings"] >= DIAG_LIMIT:
        hints.append(f"{v['diagSettings']} diagnostic settings (the limit is {DIAG_LIMIT}): remove one before the factory adds its audit setting")
    return "; ".join(hints) or "ok"


def names_of(policy):
    """The DNS names a certificate covers (its SANs, or the CN when it has none) as one comparable string."""
    names = {n.lower() for n in (getattr(policy, "san_dns_names", None) or [])}
    if not names and policy is not None and policy.subject:
        for part in policy.subject.split(","):
            part = part.strip()
            if part.upper().startswith("CN="):
                names.add(part[3:].lower())
    return ",".join(sorted(names))


def duplicate_groups(certs):
    """Certificates that cover the same names in more than one vault: each group is orders the factory replaces with one.

    Replicas (tag kvsync-origin), disabled certificates and vaults that could not be read are left out.
    """
    groups = {}
    for c in certs:
        if c.get("error") or not c.get("enabled") or not c.get("names") or "kvsync-origin=" in (c.get("tags") or ""):
            continue
        groups.setdefault(c["names"], []).append(c)
    out = []
    for names, rows in sorted(groups.items()):
        vaults = sorted({r["vault"] for r in rows})
        if len(vaults) > 1:
            out.append({"names": names, "vaults": vaults, "certificates": len(rows)})
    return out


def cert_rows(cred, vault):
    """One row per certificate, or a single row with `error` when the vault cannot be read."""
    out = []
    try:
        client = CertificateClient(vault["uri"], cred)
        for props in client.list_properties_of_certificates():
            c = client.get_certificate(props.name)
            p = c.policy
            expires = props.expires_on
            days = (expires - dt.datetime.now(dt.timezone.utc)).days if expires else None
            tags = props.tags or {}
            out.append({
                "vault": vault["name"], "certificate": props.name, "enabled": props.enabled,
                "expires": expires.strftime("%Y-%m-%d") if expires else "", "days_left": days,
                "issuer": (p.issuer_name if p else "") or "", "exportable": getattr(p, "exportable", None),
                "key": f"{getattr(p.key_type, 'value', p.key_type)}-{p.key_size}" if p and p.key_type else "",
                "subject": (p.subject if p else "") or "", "names": names_of(p),
                "thumbprint": props.x509_thumbprint.hex().upper() if props.x509_thumbprint else "",
                "tags": ",".join(f"{k}={v}" for k, v in tags.items() if k in SYNC_TAGS),
                "error": "",
            })
    except HttpResponseError as e:
        out.append({"vault": vault["name"], "certificate": "", "error": f"{e.status_code} {e.reason}: {(e.message or '').splitlines()[0][:110]}"})
    except Exception as e:  # noqa: BLE001  (DNS / firewall failures must be reported, not hidden)
        out.append({"vault": vault["name"], "certificate": "", "error": f"{type(e).__name__}: {str(e)[:120]}"})
    return out


def cert_hint(c):
    if c.get("error"):
        return "cannot read this vault"
    if not c["enabled"]:
        return "disabled: not copied"
    if c["exportable"] is False:
        return "NOT exportable: cannot be copied. Re-issue as an exportable certificate in the factory vault"
    if "kvsync-origin=" in (c["tags"] or ""):
        return "replica written by the sync function (see tag kvsync-origin): never renew or edit it here"
    issuer = (c["issuer"] or "").lower()
    if issuer == "self":
        return "self-signed"
    if issuer == "unknown":
        return "CSR mode: Key Vault never renews it. Candidate for the renewal function"
    if issuer:
        return f"issuer {c['issuer']}: Key Vault renews it by itself. Candidate source for kvsync=all"
    return ""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--subscription", action="append", default=[], help="limit to this subscription id (repeatable)")
    ap.add_argument("--vault", action="append", default=[], help="limit to the vault with this name (repeatable), e.g. to inventory one wave")
    ap.add_argument("--certs", action="store_true", help="also list the certificates of every vault (data plane)")
    ap.add_argument("--diag", action="store_true", help="also count the diagnostic settings of every vault (the factory adds one; the limit is 5)")
    ap.add_argument("--csv", help="write the vault (or certificate, with --certs) rows to this CSV file")
    ap.add_argument("--json", help="write everything to this JSON file")
    a = ap.parse_args()

    cred = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    vaults = vault_rows(cred, a.subscription)
    if a.vault:
        wanted = {n.lower() for n in a.vault}
        missing = wanted - {v["name"].lower() for v in vaults}
        vaults = [v for v in vaults if v["name"].lower() in wanted]
        if missing:
            print(f"not found (check the name and the subscription filter): {', '.join(sorted(missing))}\n")
    print(f"{len(vaults)} vault(s)\n")
    for v in vaults:
        normalise(v)
        v["permission_model"] = model(v)
        if a.diag:
            v["diagSettings"] = diag_count(cred, v)
        v["hint"] = vault_hint(v)
        diag = f" diag={'?' if v['diagSettings'] is None else v['diagSettings']}" if a.diag else ""
        print(f"{v['name']:<24} {v['subscriptionId'][:8]}  {v['location']:<12} {v['permission_model']:<13} purge={v['purge']:<4} "
              f"public={v['publicAccess']:<8} firewall={v['firewall']:<5} pe={v['privateEndpoints']}{diag}  -> {v['hint']}")

    certs = []
    if a.certs:
        print()
        for v in vaults:
            for c in cert_rows(cred, v):
                c["hint"] = cert_hint(c)
                certs.append(c)
                if c.get("error"):
                    print(f"{c['vault']:<24} ERROR {c['error']}")
                else:
                    print(f"{c['vault']:<24} {c['certificate']:<26} enabled={str(c['enabled']):<5} exp={c['expires']} ({c['days_left']}d) "
                          f"issuer={c['issuer'] or '-':<8} exportable={str(c['exportable']):<5} {c['key']:<9} thumb={c['thumbprint'][:8] or '-':<8} "
                          f"{c['tags']}  -> {c['hint']}")
        dupes = duplicate_groups(certs)
        print()
        if dupes:
            print("Same names in more than one vault. Each line is one certificate the factory could issue once and copy:")
            for g in dupes:
                print(f"  {g['names']}: {g['certificates']} certificates in {len(g['vaults'])} vaults ({', '.join(g['vaults'])})")
        else:
            print("No certificate covers the same names in more than one vault.")
    if a.csv:
        rows = certs if a.certs else vaults
        keys = sorted({k for r in rows for k in r}) if rows else []
        with open(a.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=keys)
            w.writeheader()
            w.writerows(rows)
        print(f"\nwrote {a.csv}")
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump({"vaults": vaults, "certificates": certs, "duplicates": duplicate_groups(certs)}, fh, indent=2, default=str)
        print(f"wrote {a.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
