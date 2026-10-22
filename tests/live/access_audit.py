#!/usr/bin/env python3
"""Least-privilege audit: what can each function identity REALLY do, on each vault?

Read-only. Uses your `az login` and needs only Reader. For the two function identities (sync, renew) it lists every role assignment,
expands each role into its data-plane actions, and checks the result against the rules of the design (docs/DESIGN-QA.md):

  R1  nothing is assigned above resource scope   (a subscription or resource-group assignment would reach vaults nobody listed)
  R2  no administrative role                     (Owner, Contributor, User Access Administrator, Key Vault Administrator/Officers ...)
  R3  no wildcard Key Vault data action, no NotDataActions trick
  R4  destination vaults: sync can read and import certificates and do nothing else; renew has no access at all
  R5  source vault: sync is read-only and, through an ABAC condition, can never read the CA credential (ca-*)
  R6  source vault: renew can create and merge certificate versions and read only the CA credential; it cannot import,
      delete, purge, back up, restore, or read keys

It also lists everybody who can read a private key on the source vault. That is the question a security reviewer asks first.

This derives permissions from the role definitions, exactly as the portal's "Check access" does. It does not call the vault as the
identities (that is only possible from inside Azure); the functional proof is the end-to-end run (tests/live/e2e.py).

Usage:  python tests/live/access_audit.py --outputs terraform/poc/outputs.json [--evidence .scratch/access-audit]
Exit code 0 = every rule holds, 1 = at least one rule is violated.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

KV = "Microsoft.KeyVault/vaults/"
ADMIN_ROLES = {
    "Owner", "Contributor", "User Access Administrator", "Role Based Access Control Administrator",
    "Key Vault Administrator", "Key Vault Data Access Administrator", "Key Vault Contributor",
    "Key Vault Certificates Officer", "Key Vault Secrets Officer", "Key Vault Crypto Officer",
}
# label, data action. Rows of the ability matrix.
ABILITIES = [
    ("read a certificate (public part)", KV + "certificates/read"),
    ("read the private key (secret value)", KV + "secrets/getSecret/action"),
    ("create a new certificate version (CSR)", KV + "certificates/create/action"),
    ("merge a signed certificate", KV + "certificates/update/action"),
    ("import a certificate", KV + "certificates/import/action"),
    ("delete a certificate", KV + "certificates/delete"),
    ("purge a certificate", KV + "certificates/purge/action"),
    ("back up a certificate", KV + "certificates/backup/action"),
    ("restore a certificate", KV + "certificates/restore/action"),
    ("write a secret", KV + "secrets/setSecret/action"),
    ("read keys", KV + "keys/read"),
]
SYNC_SOURCE_OK = {KV + "certificates/read", KV + "secrets/getSecret/action", KV + "secrets/readMetadata/action", KV + "keys/read"}
SYNC_DEST_OK = {KV + "certificates/read", KV + "certificates/import/action"}
RENEW_SOURCE_OK = {
    KV + "certificates/read", KV + "certificates/create/action", KV + "certificates/update/action",
    KV + "secrets/getSecret/action", KV + "secrets/readMetadata/action",
}


def az(*args: str):
    exe = shutil.which("az") or shutil.which("az.cmd")
    r = subprocess.run([exe, *args, "--only-show-errors", "-o", "json"], capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise SystemExit(f"az {' '.join(args[:4])} failed: {r.stderr.strip()[:400]}")
    return json.loads(r.stdout) if r.stdout.strip() else None


def load(path: str) -> dict:
    out = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    return {k: (v["value"] if isinstance(v, dict) and "value" in v else v) for k, v in out.items()}


def sub_of(resource_id: str) -> str:
    return resource_id.split("/")[2]


def relates(scope: str, vault_id: str) -> bool:
    s, v = scope.lower().rstrip("/"), vault_id.lower().rstrip("/")
    return v == s or v.startswith(s + "/") or s.startswith(v + "/")


def matches(pattern: str, action: str) -> bool:
    return re.fullmatch(re.escape(pattern).replace(r"\*", ".*"), action, re.I) is not None


class Roles:
    def __init__(self) -> None:
        self.cache: dict = {}

    def get(self, role_definition_id: str) -> dict:
        if role_definition_id not in self.cache:
            d = az("rest", "--method", "get", "--url", f"{role_definition_id}?api-version=2022-04-01")
            p = d["properties"]
            allow, deny = [], []
            for perm in p["permissions"]:
                allow += perm.get("dataActions", [])
                deny += perm.get("notDataActions", [])
            self.cache[role_definition_id] = {"name": p["roleName"], "allow": allow, "deny": deny,
                                              "control": [a for perm in p["permissions"] for a in perm.get("actions", [])]}
        return self.cache[role_definition_id]


def can(role: dict, action: str) -> bool:
    return any(matches(a, action) for a in role["allow"]) and not any(matches(a, action) for a in role["deny"])


def assignments_for(principal_id: str, subs: list) -> list:
    seen, rows = set(), []
    for s in subs:
        for a in az("role", "assignment", "list", "--all", "--assignee", principal_id, "--include-inherited", "--subscription", s) or []:
            if a["id"] not in seen:
                seen.add(a["id"])
                rows.append(a)
    return rows


def short(cond: str | None) -> str:
    if not cond:
        return ""
    m = re.search(r"(StringNotStartsWith|StringStartsWith)\s*'([^']*)'", cond)
    return f"ABAC: secret name {'does not start' if m and m.group(1) == 'StringNotStartsWith' else 'starts'} with '{m.group(2)}'" if m else "ABAC condition"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--outputs", required=True, help="terraform output -json of the proof-of-concept root module")
    ap.add_argument("--evidence", default=".scratch/access-audit", help="writes <value>.json and <value>.md")
    a = ap.parse_args()

    o = load(a.outputs)
    src = o["source_vault"]["id"]
    dests = {k: v["id"] for k, v in o["destination_vaults"].items()}
    ids = {k: v["principal_id"] for k, v in o["identities"].items()}
    names = {v["principal_id"]: v["name"] for v in o["identities"].values()}
    subs = sorted({sub_of(src), *[sub_of(v) for v in dests.values()]})
    roles = Roles()

    vaults = {"source": src, **{f"dest-{k}": v for k, v in dests.items()}}
    results, findings, matrix = [], [], {}

    def check(rule: str, ok: bool, text: str) -> None:
        results.append({"rule": rule, "pass": ok, "text": text})
        print(f"{'PASS' if ok else 'FAIL'}  {rule}  {text}")

    print(f"=== access audit: {len(ids)} function identities, {len(vaults)} vaults, subscriptions {', '.join(s[:8] for s in subs)} ===")
    per_identity = {}
    for who, pid in ids.items():
        rows = assignments_for(pid, subs)
        per_identity[who] = rows
        print(f"\n{who} ({names[pid]}): {len(rows)} role assignment(s)")
        for r in sorted(rows, key=lambda r: r["scope"]):
            tail = "/".join(r["scope"].split("/")[-3:])
            print(f"    {r['roleDefinitionName']:<34} {tail}   {short(r.get('condition'))}")

    # R1 / R2
    for who, rows in per_identity.items():
        high = [r for r in rows if r["scope"].strip("/").count("/") < 7]  # subscription, resource group or higher
        check("R1", not high, f"{who}: every assignment is at resource scope" if not high else f"{who}: assignments above resource scope: " + ", ".join(f"{r['roleDefinitionName']}@{r['scope']}" for r in high))
        adm = [r["roleDefinitionName"] for r in rows if r["roleDefinitionName"] in ADMIN_ROLES]
        check("R2", not adm, f"{who}: no administrative role" if not adm else f"{who}: administrative roles: {adm}")
        # Only Key Vault matters here. Storage roles legitimately carry wildcards on the identity's own storage account.
        wild = []
        for r in rows:
            d = roles.get(r["roleDefinitionId"])
            if any(x.strip() == "*" or (x.startswith("Microsoft.KeyVault") and "*" in x) for x in d["allow"]) or any(x.startswith("Microsoft.KeyVault") for x in d["deny"]):
                wild.append(d["name"])
        check("R3", not wild, f"{who}: no wildcard Key Vault data actions and no NotDataActions" if not wild else f"{who}: wildcard or NotDataActions in: {sorted(set(wild))}")

    # effective data actions per identity per vault
    probes = {x for _, x in ABILITIES} | SYNC_SOURCE_OK | SYNC_DEST_OK | RENEW_SOURCE_OK
    eff: dict = {}
    for who, rows in per_identity.items():
        for vname, vid in vaults.items():
            allowed, conditional, declared, used = set(), set(), set(), []
            for r in rows:
                if not relates(r["scope"], vid):
                    continue
                d = roles.get(r["roleDefinitionId"])
                used.append(d["name"] + (f" [{short(r.get('condition'))}]" if r.get("condition") else ""))
                declared |= set(d["allow"])
                for act in probes:
                    if can(d, act):
                        (conditional if (r.get("condition") and act.endswith("getSecret/action")) else allowed).add(act)
            eff[(who, vname)] = {"allowed": allowed, "conditional": conditional, "declared": declared, "roles": used}

    print()
    fmt = lambda xs: sorted(x.replace(KV, "") for x in xs)
    # R4: destinations
    for k in dests:
        sd = eff[("sync", f"dest-{k}")]["declared"]
        check("R4", sd == SYNC_DEST_OK, f"dest-{k}: sync can {fmt(sd)}" + ("" if sd == SYNC_DEST_OK else f"   (expected exactly {fmt(SYNC_DEST_OK)})"))
        rd = eff[("renew", f"dest-{k}")]["declared"]
        check("R4", not rd, f"dest-{k}: renew has no data access" if not rd else f"dest-{k}: renew can {fmt(rd)}")
    # R5: source, sync
    s = eff[("sync", "source")]
    check("R5", bool(s["declared"]) and s["declared"] <= SYNC_SOURCE_OK, f"source: sync can {fmt(s['declared'])}" + ("" if s["declared"] <= SYNC_SOURCE_OK else f"   (beyond: {fmt(s['declared'] - SYNC_SOURCE_OK)})"))
    cond_ok = any("ABAC" in x for x in s["roles"]) and KV + "secrets/getSecret/action" in s["conditional"] and KV + "secrets/getSecret/action" not in s["allowed"]
    check("R5", cond_ok, "source: sync's private-key read is limited by an ABAC condition (it cannot read the CA credential, ca-*)" if cond_ok
          else "source: sync's private-key read has NO ABAC condition: it can read every secret in the vault, including the CA credential")
    # R6: source, renew
    r = eff[("renew", "source")]
    need = {KV + "certificates/create/action", KV + "certificates/update/action"}
    check("R6", r["declared"] <= RENEW_SOURCE_OK and need <= r["declared"], f"source: renew can {fmt(r['declared'])}" + ("" if r["declared"] <= RENEW_SOURCE_OK else f"   (beyond: {fmt(r['declared'] - RENEW_SOURCE_OK)})"))
    cond_r = KV + "secrets/getSecret/action" in r["conditional"] and KV + "secrets/getSecret/action" not in r["allowed"]
    check("R6", cond_r, "source: renew can read secrets only under an ABAC condition (ca-*)" if cond_r else "source: renew can read ANY secret")

    # ability matrix
    cols = [(who, v) for v in vaults for who in ("sync", "renew")]
    print("\nWhat each identity can do (control derived from role definitions; * = only under an ABAC condition)")
    head = f"{'':<40}" + "".join(f"{who + '@' + v:<18}" for who, v in cols)
    print(head)
    md = ["| ability | " + " | ".join(f"{who} @ {v}" for who, v in cols) + " |", "|---|" + "---|" * len(cols)]
    for label, act in ABILITIES:
        cells = []
        for who, v in cols:
            e = eff[(who, v)]
            cells.append("yes" if act in e["allowed"] else "yes*" if act in e["conditional"] else "-")
        print(f"{label:<40}" + "".join(f"{c:<18}" for c in cells))
        md.append(f"| {label} | " + " | ".join(cells) + " |")

    # who can read a private key on the source vault
    print("\nEveryone who can read a private key on the source vault (direct, inherited, or through a group):")
    readers = []
    for ra in az("role", "assignment", "list", "--scope", src, "--include-inherited", "--subscription", sub_of(src)) or []:
        d = roles.get(ra["roleDefinitionId"])
        if can(d, KV + "secrets/getSecret/action"):
            who = names.get(ra["principalId"]) or ra.get("principalName") or ra["principalId"]
            readers.append({"principal": who, "type": ra.get("principalType"), "role": d["name"], "scope": ra["scope"], "condition": short(ra.get("condition"))})
            print(f"    {who:<42} {ra.get('principalType', ''):<16} {d['name']:<32} {short(ra.get('condition'))}")
    if not readers:
        print("    (none found)")

    ok = all(x["pass"] for x in results)
    base = Path(a.evidence)
    base.parent.mkdir(parents=True, exist_ok=True)
    base.with_suffix(".json").write_text(json.dumps({"results": results, "readers": readers, "roles": {k: v["name"] for k, v in roles.cache.items()},
                                                    "effective": {f"{w}@{v}": {"allowed": sorted(e["allowed"]), "conditional": sorted(e["conditional"]), "declared": sorted(e["declared"]), "roles": e["roles"]} for (w, v), e in eff.items()}},
                                                   indent=2), encoding="utf-8")
    base.with_suffix(".md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"\n{'ALL RULES HOLD' if ok else 'RULE VIOLATIONS FOUND'}  ({sum(x['pass'] for x in results)}/{len(results)} checks)   evidence: {base}.json / .md")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
