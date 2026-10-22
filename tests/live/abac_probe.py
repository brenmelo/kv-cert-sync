"""The ABAC condition on the SYNC identity, proven through the DEPLOYED function (not through a role definition).

The sync identity holds *Key Vault Certificate User* on the source vault with the condition "the secret name does not start
with 'ca-'" (the CA credential lives under that prefix). The private key of a certificate is a secret with the SAME name as the
certificate, so a certificate named ca-* is the sharpest probe: the function is told to copy it, and the vault must refuse to
hand over the key.

    terraform -chdir=terraform/poc output -json > outputs.json
    python tests/live/abac_probe.py --outputs outputs.json --wait-until 07:40 --evidence .scratch/abac-probe.json

arrange  two exportable self-signed certificates in the source vault WITHOUT the opt-in tag:  abac-ok-<run> and ca-abac-<run>
wait     until --wait-until (UTC, HH:MM), so that a changed role assignment has had its documented propagation time
act      add kvsync=all to both. A tag change fires no event; the next timer sweep (5 min in the POC, 15 min by default) finds them
assert   abac-ok-<run>  is copied to both destinations (a normal name still works under the condition)
         ca-abac-<run>  is NOT copied anywhere, and the function logged a failure that names the refusal (Forbidden)
         the vault's own audit log shows SecretGet on ca-abac-<run> answered 403 for the sync identity (best effort: the
         audit log can lag; if it has not arrived in time the probe says so and does not fail)
clean    delete the probes
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import edge  # noqa: E402  (shared helpers: say / check / self_signed / thumb / cred)

from azure.core.exceptions import ResourceNotFoundError  # noqa: E402
from azure.keyvault.certificates import CertificateClient  # noqa: E402
from kvsync.sync import vault_name  # noqa: E402


def la(workspace: str, query: str, timespan: str = "PT2H") -> list[dict]:
    token = edge.cred.get_token("https://api.loganalytics.io/.default").token
    req = urllib.request.Request(
        f"https://api.loganalytics.io/v1/workspaces/{workspace}/query",
        data=json.dumps({"query": query, "timespan": timespan}).encode(),
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    data = json.load(urllib.request.urlopen(req, timeout=60))
    table = data["tables"][0]
    cols = [c["name"] for c in table["columns"]]
    return [dict(zip(cols, row)) for row in table["rows"]]


def out_value(out: dict, key: str):
    v = out[key]
    return v["value"] if isinstance(v, dict) and "value" in v and len(v) <= 3 and "type" in v else v


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--outputs", required=True, help="`terraform output -json` of the stack, saved to a file")
    p.add_argument("--run", default=dt.datetime.now(dt.timezone.utc).strftime("%H%M"), help="keeps certificate names unique")
    p.add_argument("--wait-until", default=None, help="UTC HH:MM; the opt-in tag is not added before this time")
    p.add_argument("--timeout-min", type=int, default=25, help="how long to wait for the sweep and for the log lines")
    p.add_argument("--evidence", default=None, help="write the results as JSON here")
    p.add_argument("--keep", action="store_true", help="do not delete the probes afterwards")
    a = p.parse_args()

    out = json.loads(Path(a.outputs).read_text(encoding="utf-8-sig"))
    src_uri = out_value(out, "source_vault")["uri"]
    dvs = out_value(out, "destination_vaults")
    workspace = out_value(out, "log_analytics_customer_id")
    sync_oid = out_value(out, "identities")["sync"]["principal_id"]
    keys = sorted(dvs)
    edge.LOG = Path(a.evidence).with_suffix(".log") if a.evidence else None

    src = CertificateClient(src_uri, edge.cred)
    dests = {k: CertificateClient(dvs[k]["uri"], edge.cred) for k in keys}
    ok_name, ca_name = f"abac-ok-{a.run}", f"ca-abac-{a.run}"
    edge.say(f"=== ABAC probe, run {a.run}: source {vault_name(src_uri)}, destinations "
             + ", ".join(f"{k}={vault_name(dvs[k]['uri'])}" for k in keys) + " ===")

    # ---------------------------------------------------------------------------------------------- ARRANGE
    thumbs = {n: edge.self_signed(src, n, exportable=True, tags={"purpose": "abac-probe"}) for n in (ok_name, ca_name)}
    edge.say(f"ARRANGE  created {ok_name} ({thumbs[ok_name][:8]}) and {ca_name} ({thumbs[ca_name][:8]}), no opt-in tag yet")

    if a.wait_until:
        hh, mm = (int(x) for x in a.wait_until.split(":"))
        now = dt.datetime.now(dt.timezone.utc)
        target = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        if target > now:
            edge.say(f"WAIT     {int((target - now).total_seconds())}s until {a.wait_until}Z (role-assignment propagation)")
            time.sleep((target - now).total_seconds())

    # ---------------------------------------------------------------------------------------------- ACT
    tagged_at = dt.datetime.now(dt.timezone.utc)
    for n in (ok_name, ca_name):
        src.update_certificate_properties(n, tags={"purpose": "abac-probe", "kvsync": "all"})
    edge.say(f"ACT      added kvsync=all to both at {tagged_at:%H:%M:%S}Z; the next timer sweep takes them")

    # ---------------------------------------------------------------------------------------------- ASSERT
    deadline = time.time() + a.timeout_min * 60
    since = (tagged_at - dt.timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    q = (f'AppTraces | where TimeGenerated > datetime({since}) | where Message has "KVSYNC" '
         f'and (Message has "{ok_name}" or Message has "{ca_name}") | project TimeGenerated, Message | order by TimeGenerated asc')
    copied: dict[str, str | None] = {}
    lines: list[dict] = []
    while time.time() < deadline:
        time.sleep(30)
        copied = {k: edge.thumb(c, ok_name) for k, c in dests.items()}
        lines = la(workspace, q)
        failed_lines = [r for r in lines if ca_name in r["Message"] and "result=failed" in r["Message"]]
        if all(copied.values()) and failed_lines:
            break
        edge.say(f"         waiting: {ok_name} in {sum(1 for v in copied.values() if v)}/{len(keys)} destinations, "
                 f"log lines for the probes: {len(lines)}")

    edge.check("A1", all(copied.get(k) == thumbs[ok_name] for k in keys),
               f"{ok_name}: a normal certificate name is still copied to every destination under the condition",
               copied=copied)
    absent = {k: edge.thumb(c, ca_name) for k, c in dests.items()}
    edge.check("A2", not any(absent.values()),
               f"{ca_name}: NOT copied to any destination (the vault refused the private key)", found=absent)
    failed_lines = [r for r in lines if ca_name in r["Message"] and "result=failed" in r["Message"]]
    refused = [r for r in failed_lines if any(w in r["Message"] for w in ("Forbidden", "403", "not authorized"))]
    edge.check("A3", bool(refused), f"{ca_name}: the function logged a failure that names the refusal",
               sample=(refused[0]["Message"][:300].replace("\n", " ") if refused else None), failure_lines=len(failed_lines))

    audit_q = ("AzureDiagnostics | where Category == 'AuditEvent' and OperationName == 'SecretGet' "
               f"and requestUri_s has '{ca_name}' | project TimeGenerated, httpStatusCode_d, ResultSignature, "
               "identity_claim_oid_g, CallerIPAddress | order by TimeGenerated asc")
    audit: list[dict] = []
    audit_deadline = time.time() + 8 * 60
    while time.time() < audit_deadline:
        try:
            audit = la(workspace, audit_q)
        except Exception as e:  # the table can be missing until the first audit row arrives
            audit = []
            edge.say(f"         audit query not ready yet: {type(e).__name__}")
        if audit:
            break
        time.sleep(45)
    if audit:
        statuses = sorted({int(r["httpStatusCode_d"]) for r in audit if r.get("httpStatusCode_d") is not None})
        oids = sorted({str(r.get("identity_claim_oid_g")).lower() for r in audit})
        edge.check("A4", 403 in statuses and sync_oid.lower() in oids,
                   f"audit log: SecretGet on {ca_name} was answered {statuses} for principal(s) {oids}",
                   expected_principal=sync_oid)
    else:
        edge.say("INFO  A4  the vault audit rows for the probe had not arrived in Log Analytics after 8 minutes; "
                 "A1-A3 stand on their own, run the audit query by hand later")

    # ---------------------------------------------------------------------------------------------- CLEAN
    if not a.keep:
        for client in [src, *dests.values()]:
            for n in (ok_name, ca_name):
                try:
                    client.begin_delete_certificate(n).wait()
                except ResourceNotFoundError:
                    pass
                except Exception as e:  # a destination may refuse: the sync identity is the only deleter we gave nothing to
                    edge.say(f"CLEAN  {n}: {type(e).__name__}")
        edge.say("CLEAN    deleted the probes (soft-deleted; purge protection keeps the names reserved)")

    if a.evidence:
        Path(a.evidence).write_text(json.dumps({"run": a.run, "results": edge.results}, indent=2), encoding="utf-8")
    edge.say("=== ABAC probe done: " + ("ALL PASSED ===" if not edge.failures else f"FAILED: {edge.failures} ==="))
    return 1 if edge.failures else 0


if __name__ == "__main__":
    sys.exit(main())
