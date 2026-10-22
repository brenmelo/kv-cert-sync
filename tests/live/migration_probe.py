"""Two migration cases that the customer runbook depends on, proven against the proof of concept.

    terraform -chdir=terraform/poc output -json > outputs.json
    python tests/live/migration_probe.py --outputs outputs.json --evidence .scratch/migration.json

adopt    A destination vault already holds a certificate of the same name that KEY VAULT RENEWS BY ITSELF (issuer Self with an
         auto-renew lifetime action: the same shape as a certificate that came from an integrated CA). The operator adopts it by
         tagging it kvsync-origin=<factory vault>, which is what the runbook tells them to do.
         A0 before the adoption its policy says "auto-renew", and the factory did not overwrite it
         A1 the next sweep writes the factory's certificate into it
         A2 after the adoption the vault no longer renews it by itself
         A3 the previous version is still in the vault (rollback is possible)
deleted  Somebody deletes a copy in a destination vault (soft delete). The next rotation at the factory cannot be written
         there, and everything else carries on.
         D0 both destinations hold the copy      D1 one copy is deleted (soft delete)
         D2 a rotation at the factory still reaches the OTHER destination
         D3 the log says what is wrong with the one that was deleted (the exact error is recorded)
         D4 after the owner RECOVERS the deleted copy the destination converges by itself
stays    The same, but the owner LEAVES the copy deleted. This is what the operator sees while nobody acts on it.
         L0 both destinations hold the copy      L1 a rotation at the factory still reaches the OTHER destination
         L2 the next timer sweep logs an ERROR line for the deleted copy (the exact line is recorded)
         L3 the `failures` alert fires (needs an earlier `failures` alert to be resolved, or no new instance appears)
         L4 after the owner RECOVERS the copy the destination converges by itself

Only certificates named mig-<run>-* are touched, and they are deleted again (and purged where purge protection is off).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import edge  # noqa: E402  (shared helpers: say / check / make_pfx / import_policy / thumb / cred)
from alerts_probe import TIMELINE, Env, alert_in, lines, now, stamp, wait_until  # noqa: E402

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError  # noqa: E402
from azure.keyvault.certificates import (  # noqa: E402
    CertificateContentType,
    CertificatePolicy,
    CertificatePolicyAction,
    LifetimeAction,
)


def describe(policy) -> dict:
    acts = [{"action": str(getattr(a.action, "value", a.action)), "lifetime_percentage": a.lifetime_percentage,
             "days_before_expiry": a.days_before_expiry} for a in (policy.lifetime_actions or [])]
    return {"issuer": policy.issuer_name, "lifetime_actions": acts}


def renews_by_itself(policy) -> bool:
    return any(str(getattr(a.action, "value", a.action)).lower() == "autorenew" for a in (policy.lifetime_actions or []))


def self_signed_autorenew(client, name: str, cn: str) -> None:
    policy = CertificatePolicy(
        issuer_name="Self", subject=f"CN={cn}", san_dns_names=[cn], exportable=True, key_type="RSA", key_size=2048, reuse_key=False,
        content_type=CertificateContentType.pkcs12, validity_in_months=3,
        lifetime_actions=[LifetimeAction(CertificatePolicyAction.auto_renew, lifetime_percentage=80)],
    )
    client.begin_create_certificate(name, policy).result(timeout=120)


def scenario_adopt(env: Env, run: str, src_name: str) -> None:
    ka, kb = env.keys[0], env.keys[1]
    da, db = env.dests[ka], env.dests[kb]
    name, cn = f"mig-{run}-adopt", f"mig-{run}-adopt.example.test"

    self_signed_autorenew(db, name, cn)
    existing = edge.thumb(db, name)
    pol0 = db.get_certificate_policy(name)
    edge.check("A0", pol0.issuer_name == "Self" and renews_by_itself(pol0),
               f"{env.dest_info[kb]['name']} already holds {name}, and Key Vault renews it by itself", policy=describe(pol0))
    stamp("destination already holds a self-renewing certificate", thumb=existing[:8])

    pfx, th = edge.make_pfx(cn)
    env.src.import_certificate(name, pfx, policy=edge.import_policy(), tags={"kvsync": "all"})
    stamp("the factory's certificate of the same name was created", thumb=th[:8])
    got_a = wait_until(lambda: edge.thumb(da, name) == th, 360, 15, f"the copy in destination {ka}")
    edge.check("A0", bool(got_a) and edge.thumb(db, name) == existing,
               f"destination {ka} received it, and destination {kb} kept its own certificate (never overwritten)")

    ver = db.get_certificate(name).properties.version
    db.update_certificate_properties(name, version=ver, tags={"kvsync-origin": src_name})
    stamp("adoption: the destination certificate was tagged", tag=f"kvsync-origin={src_name}")
    t_tag = time.time()
    took = wait_until(lambda: edge.thumb(db, name) == th, 14 * 60, 15, "the sweep to take over the adopted certificate")
    edge.check("A1", bool(took), f"the next sweep wrote the factory's certificate into {kb} "
               f"({(time.time() - t_tag) / 60:.1f} min after tagging)", minutes=round((time.time() - t_tag) / 60, 1))
    if not took:
        return

    pol1 = db.get_certificate_policy(name)
    edge.check("A2", not renews_by_itself(pol1),
               "after the adoption Key Vault no longer renews it by itself" if not renews_by_itself(pol1)
               else "HAZARD: Key Vault still renews it by itself after the adoption; remove the auto-renew action first",
               policy_before=describe(pol0), policy_after=describe(pol1))
    versions = list(db.list_properties_of_certificate_versions(name))
    cur = db.get_certificate(name).properties.tags or {}
    edge.check("A3", len(versions) >= 2 and cur.get("kvsync-origin") == src_name,
               "the previous version is still in the vault, and the new one is tagged as a copy", versions=len(versions))


def scenario_deleted(env: Env, run: str) -> None:
    ka, kb = env.keys[0], env.keys[1]
    da, db = env.dests[ka], env.dests[kb]
    name, cn = f"mig-{run}-del", f"mig-{run}-del.example.test"

    pfx1, th1 = edge.make_pfx(cn)
    env.src.import_certificate(name, pfx1, policy=edge.import_policy(), tags={"kvsync": "all"})
    stamp("certificate created at the factory", thumb=th1[:8])
    both = wait_until(lambda: edge.thumb(da, name) == th1 and edge.thumb(db, name) == th1, 420, 15, "the copy in both destinations")
    edge.check("D0", bool(both), "both destinations hold the copy")
    if not both:
        return

    db.begin_delete_certificate(name).wait()
    try:
        deleted = db.get_deleted_certificate(name)
        in_bin = deleted is not None
    except ResourceNotFoundError:
        in_bin = False
    edge.check("D1", in_bin and edge.thumb(db, name) is None, f"the copy in {kb} is soft-deleted (still reserved, not readable)")
    stamp("the copy in one destination was deleted", dest=kb)
    t_rot = now()

    pfx2, th2 = edge.make_pfx(cn)
    env.src.import_certificate(name, pfx2, policy=edge.import_policy(), tags={"kvsync": "all"})
    stamp("the factory rotated the certificate", thumb=th2[:8])
    other = wait_until(lambda: edge.thumb(da, name) == th2, 360, 10, f"the rotation in destination {ka}")
    edge.check("D2", bool(other), f"the rotation reached destination {ka} although {kb} could not take it")

    def failure_line():
        rows = [r for r in lines(env, name, t_rot) if f"dest={kb}" in r["Message"]
                and re.search(r"result=(retrying|failed-transient|failed-permanent)", r["Message"])]
        return rows[0] if rows else None

    row = wait_until(failure_line, 420, 20, "a failure line for the deleted copy")
    edge.check("D3", bool(row), "the log carries one standard failure line for the deleted copy",
               line=(row or {}).get("Message", "")[:900], severity=(row or {}).get("SeverityLevel"))

    db.begin_recover_deleted_certificate(name).wait()
    stamp("the owner recovered the deleted copy", dest=kb)
    t_rec = time.time()
    fixed = wait_until(lambda: edge.thumb(db, name) == th2, 12 * 60, 15, "the recovered copy to converge")
    edge.check("D4", bool(fixed), f"after the recovery {kb} converged to the new version by itself "
               f"({(time.time() - t_rec):.0f} s later, no other step)", seconds=round(time.time() - t_rec))


def scenario_stays(env: Env, run: str) -> None:
    ka, kb = env.keys[0], env.keys[1]
    da, db = env.dests[ka], env.dests[kb]
    name, cn = f"mig-{run}-stay", f"mig-{run}-stay.example.test"

    pfx1, th1 = edge.make_pfx(cn)
    env.src.import_certificate(name, pfx1, policy=edge.import_policy(), tags={"kvsync": "all"})
    stamp("certificate created at the factory", thumb=th1[:8])
    both = wait_until(lambda: edge.thumb(da, name) == th1 and edge.thumb(db, name) == th1, 420, 15, "the copy in both destinations")
    edge.check("L0", bool(both), "both destinations hold the copy")
    if not both:
        return

    db.begin_delete_certificate(name).wait()
    t_del = now()
    stamp("the copy in one destination was deleted, and left deleted", dest=kb)
    pfx2, th2 = edge.make_pfx(cn)
    env.src.import_certificate(name, pfx2, policy=edge.import_policy(), tags={"kvsync": "all"})
    stamp("the factory rotated the certificate", thumb=th2[:8])
    other = wait_until(lambda: edge.thumb(da, name) == th2, 360, 10, f"the rotation in destination {ka}")
    edge.check("L1", bool(other), f"the rotation reached destination {ka} although {kb} could not take it")

    def sweep_line():
        rows = [r for r in lines(env, name, t_del) if f"dest={kb}" in r["Message"] and "trigger=timer" in r["Message"]
                and re.search(r"result=failed-(transient|permanent)", r["Message"])]
        return rows[0] if rows else None

    row = wait_until(sweep_line, 12 * 60, 20, "the timer sweep's failure line")
    edge.check("L2", bool(row), "the next timer sweep logs an ERROR line for the copy that is still deleted",
               line=(row or {}).get("Message", "")[:900], severity=(row or {}).get("SeverityLevel"),
               logged_utc=str((row or {}).get("TimeGenerated")))
    retries = [r for r in lines(env, name, t_del) if f"dest={kb}" in r["Message"] and "result=retrying" in r["Message"]]
    stamp("event-path attempts logged so far for the deleted copy", count=len(retries),
          times=[str(r["TimeGenerated"])[11:19] for r in retries])

    fired = wait_until(alert_in(env, "alert-kvsync-failures-", t_del, "Fired"), 10 * 60, 20, "the failures alert")
    edge.check("L3", bool(fired), "the failures alert fired for it", alert=fired)

    db.begin_recover_deleted_certificate(name).wait()
    stamp("the owner recovered the deleted copy", dest=kb)
    t_rec = time.time()
    fixed = wait_until(lambda: edge.thumb(db, name) == th2, 12 * 60, 15, "the recovered copy to converge")
    edge.check("L4", bool(fixed), f"after the recovery {kb} converged to the new version by itself "
               f"({(time.time() - t_rec):.0f} s later, no other step)", seconds=round(time.time() - t_rec))


def clean(env: Env, run: str) -> None:
    names = [f"mig-{run}-adopt", f"mig-{run}-del", f"mig-{run}-stay"]
    for client, label in [(env.src, "source")] + [(env.dests[k], k) for k in env.keys]:
        for name in names:
            try:
                client.begin_delete_certificate(name).wait()
            except ResourceNotFoundError:
                continue
            except HttpResponseError as e:
                edge.say(f"CLEAN  {label}/{name}: {' '.join(str(e).split())[:120]}")
                continue
            try:
                client.purge_deleted_certificate(name)  # refused where purge protection is on: the name stays reserved, harmless
            except HttpResponseError:
                pass
    edge.say("CLEAN  deleted the test certificates (purged where purge protection is off)")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--outputs", required=True, help="`terraform output -json` of the stack, saved to a file")
    p.add_argument("--run", default=now().strftime("%H%M"), help="keeps certificate names unique")
    p.add_argument("--only", choices=["adopt", "deleted", "stays"], default=None,
                   help="default: adopt and deleted (the `stays` case takes about 20 minutes and raises a `failures` alert, so it is opt-in)")
    p.add_argument("--evidence", default=None, help="write the results as JSON here (the log goes next to it)")
    p.add_argument("--keep", action="store_true", help="do not delete the test certificates afterwards")
    a = p.parse_args()

    env = Env(json.loads(Path(a.outputs).read_text(encoding="utf-8-sig")))
    edge.LOG = Path(a.evidence).with_suffix(".log") if a.evidence else None
    src_name = edge.vault_name(env.src_uri)
    edge.say(f"=== migration probe, run {a.run}: source {src_name}, destinations "
             + ", ".join(f"{k}={env.dest_info[k]['name']}" for k in env.keys) + " ===")
    try:
        if a.only in (None, "adopt"):
            scenario_adopt(env, a.run, src_name)
        if a.only in (None, "deleted"):
            scenario_deleted(env, a.run)
        if a.only == "stays":
            scenario_stays(env, a.run)
    finally:
        if not a.keep:
            clean(env, a.run)
        if a.evidence:
            Path(a.evidence).write_text(json.dumps({"run": a.run, "finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                                                    "timeline": TIMELINE, "results": edge.results}, indent=2), encoding="utf-8")
    edge.say("=== migration probe done: " + ("ALL PASSED ===" if not edge.failures else f"FAILED: {edge.failures} ==="))
    return 1 if edge.failures else 0


if __name__ == "__main__":
    sys.exit(main())
