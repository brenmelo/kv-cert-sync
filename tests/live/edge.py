"""Edge cases of the SYNC function, run against a DEPLOYED stack.

    az login
    python tests/live/edge.py --outputs terraform/poc/outputs.json --run r1

The script ARRANGES every certificate first, waits once, and then ASSERTS everything. Key Vault -> Event Grid delivery is
not instant (measured: a merge is delivered in seconds, but the event for a freshly created self-signed certificate took
about two minutes), and a negative assertion ("was NOT copied") only means something after the event had time to arrive.

Every test certificate lives in the SOURCE vault, is throw-away, and never touches a certificate authority.

  T2  non-exportable certificate, tagged               -> permanent failure, nothing is copied, no retry storm
  T3  the tag names ONE destination                    -> only that destination receives it
  T4  a destination already holds an UNMANAGED cert    -> it is never overwritten; the other destination still syncs
  T5  loop guard                                       -> a copy is never replicated again (function logic, run locally)
  T7  the source certificate is disabled               -> skipped
  T8  a PFX IMPORTED into the source                   -> copied to every destination (the "download the PFX, import it" path)
  T6  the opt-in tag is added AFTER the event was gone -> the timer sweep copies it (the safety net)
  T9  ADOPT the unmanaged certificate of T4            -> after tagging it kvsync-origin=<source vault> the next sweep takes over,
                                                          and the unmanaged version stays behind as an older version (rollback)

The operator needs Key Vault Administrator on the three vaults (the proof-of-concept stack grants it through
`operator_object_id`). The script deletes what it created at the end unless you pass --keep.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "sync"))

from azure.core.exceptions import ResourceNotFoundError  # noqa: E402
from azure.identity import AzureCliCredential  # noqa: E402
from azure.keyvault.certificates import CertificateClient, CertificateContentType, CertificatePolicy  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.hazmat.primitives.serialization import pkcs12  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from kvsync.sync import Context, Dest, sync_certificate, vault_name  # noqa: E402

EVENT_BUDGET = 170  # seconds after creation before a NEGATIVE assertion is meaningful
POS_TIMEOUT = 300  # seconds to wait for a POSITIVE outcome that rides on an event

cred = AzureCliCredential(process_timeout=90)
results: list[dict] = []
failures: list[str] = []
LOG: Path | None = None


def say(msg: str) -> None:
    line = f"{dt.datetime.now(dt.timezone.utc).strftime('%H:%M:%S')}Z {msg}"
    print(line, flush=True)
    if LOG:
        with LOG.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


def check(test: str, ok: bool, label: str, **detail) -> None:
    say(("PASS  " if ok else "FAIL  ") + f"{test}  {label}")
    results.append({"test": test, "ok": bool(ok), "label": label, **detail})
    if not ok:
        failures.append(f"{test} {label}")


def thumb(client: CertificateClient, name: str):
    try:
        return client.get_certificate(name).properties.x509_thumbprint.hex().upper()
    except ResourceNotFoundError:
        return None


def self_signed(client: CertificateClient, name: str, *, exportable: bool, tags, enabled: bool = True) -> str:
    cn = f"{name}.example.test"
    policy = CertificatePolicy(
        issuer_name="Self", subject=f"CN={cn}", san_dns_names=[cn], exportable=exportable, key_type="RSA",
        key_size=2048, reuse_key=False, content_type=CertificateContentType.pkcs12, validity_in_months=3,
    )
    client.begin_create_certificate(name, policy, enabled=enabled, tags=tags).result(timeout=120)
    return thumb(client, name)


def make_pfx(cn: str, days: int = 60) -> tuple[bytes, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    pfx = pkcs12.serialize_key_and_certificates(cn.encode(), key, cert, None, serialization.NoEncryption())
    return pfx, cert.fingerprint(hashes.SHA1()).hex().upper()


def import_policy() -> CertificatePolicy:
    return CertificatePolicy(issuer_name="Unknown", exportable=True, key_type="RSA", key_size=2048,
                             content_type=CertificateContentType.pkcs12)


def main() -> int:
    global LOG
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--outputs", required=True, help="`terraform output -json` of the stack, saved to a file")
    p.add_argument("--run", default="r1", help="keeps certificate names unique between runs")
    p.add_argument("--evidence", default=None, help="write the results as JSON here")
    p.add_argument("--timer-timeout-min", type=int, default=18)
    p.add_argument("--skip-timer", action="store_true", help="skip T6 and T9 (they wait for the next timer sweep)")
    p.add_argument("--keep", action="store_true", help="do not delete the test certificates afterwards")
    a = p.parse_args()

    out = json.loads(Path(a.outputs).read_text(encoding="utf-8-sig"))
    src_uri = out["source_vault"]["value"]["uri"] if "value" in out.get("source_vault", {}) else out["source_vault"]["uri"]
    dvs = out["destination_vaults"]["value"] if "value" in out["destination_vaults"] else out["destination_vaults"]
    keys = sorted(dvs)
    ka, kb = keys[0], keys[1]
    ua, ub = dvs[ka]["uri"], dvs[kb]["uri"]
    LOG = Path(a.evidence).with_suffix(".log") if a.evidence else None

    src, da, db = (CertificateClient(u, cred) for u in (src_uri, ua, ub))
    src_name = vault_name(src_uri)
    N = {k: f"edge-{a.run}-{v}" for k, v in dict(
        t2="non-exportable", t3="one-destination", t4="collision", t7="disabled", t8="imported-pfx", t6="late-optin").items()}

    say(f"=== edge tests, run {a.run}: source {src_name}, destinations {ka}={vault_name(ua)} {kb}={vault_name(ub)} ===")

    # ---------------------------------------------------------------------------------------------- ARRANGE
    th: dict[str, str] = {}
    t0: dict[str, float] = {}

    th["t2"] = self_signed(src, N["t2"], exportable=False, tags={"kvsync": "all"}); t0["t2"] = time.time()
    say(f"T2  created {N['t2']} (NOT exportable, kvsync=all)")

    th["t3"] = self_signed(src, N["t3"], exportable=True, tags={"kvsync": kb}); t0["t3"] = time.time()
    say(f"T3  created {N['t3']} (kvsync={kb}: only that destination is selected)")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{N['t4']}.example.test")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=60))
        .sign(key, hashes.SHA256())
    )
    pfx = pkcs12.serialize_key_and_certificates(N["t4"].encode(), key, cert, None, serialization.NoEncryption())
    db.import_certificate(N["t4"], pfx, policy=import_policy())  # an operator-owned certificate: no kvsync-origin tag
    unmanaged = thumb(db, N["t4"])
    th["t4"] = self_signed(src, N["t4"], exportable=True, tags={"kvsync": "all"}); t0["t4"] = time.time()
    say(f"T4  {kb} already holds an UNMANAGED {N['t4']} ({unmanaged[:8]}); the source certificate was created ({th['t4'][:8]})")

    th["t7"] = self_signed(src, N["t7"], exportable=True, tags={"kvsync": "all"}, enabled=False); t0["t7"] = time.time()
    say(f"T7  created {N['t7']} (DISABLED, kvsync=all)")

    pfx8, th["t8"] = make_pfx(f"{N['t8']}.example.test")
    src.import_certificate(N["t8"], pfx8, policy=import_policy(), tags={"kvsync": "all"}); t0["t8"] = time.time()
    say(f"T8  IMPORTED a PFX as {N['t8']} into the source (kvsync=all, thumbprint {th['t8'][:8]})")

    th["t6"] = self_signed(src, N["t6"], exportable=True, tags=None); t0["t6"] = time.time()
    say(f"T6  created {N['t6']} WITHOUT the opt-in tag")

    # ---------------------------------------------------------------------------------------------- WATCH
    want = {"t3": [(db, kb)], "t4": [(da, ka)], "t8": [(da, ka), (db, kb)]}
    total = sum(len(v) for v in want.values())
    seen: dict[tuple[str, str], float] = {}
    say(f"WATCH  up to {POS_TIMEOUT}s for the {total} expected copies (T3, T4, T8)")
    deadline = time.time() + POS_TIMEOUT
    while time.time() < deadline and len(seen) < total:
        for test, targets in want.items():
            for client, label in targets:
                if (test, label) not in seen and thumb(client, N[test]) == th[test]:
                    seen[(test, label)] = time.time() - t0[test]
                    say(f"       {test.upper()} appeared in {label} {seen[(test, label)]:.0f}s after the source certificate was created")
        time.sleep(4)

    wait_neg = max(t0.values()) + EVENT_BUDGET - time.time()
    if wait_neg > 0:
        say(f"WATCH  {wait_neg:.0f}s more, so that every NEGATIVE assertion comes after its event had time to arrive")
        time.sleep(wait_neg)

    # ---------------------------------------------------------------------------------------------- ASSERT
    check("T2", thumb(da, N["t2"]) is None and thumb(db, N["t2"]) is None,
          "non-exportable certificate: nothing copied to either destination (permanent failure)")

    check("T3", (("t3", kb) in seen) and thumb(da, N["t3"]) is None,
          f"only {kb} received the certificate; {ka} did not (tag selector respected)",
          seconds=round(seen.get(("t3", kb), 0)))

    check("T4", ("t4", ka) in seen and thumb(db, N["t4"]) == unmanaged and unmanaged != th["t4"],
          f"{ka} (no conflict) received it; {kb} kept the UNMANAGED certificate, it was NOT overwritten",
          seconds=round(seen.get(("t4", ka), 0)))

    check("T7", thumb(da, N["t7"]) is None and thumb(db, N["t7"]) is None, "disabled source certificate not copied")

    check("T8", ("t8", ka) in seen and ("t8", kb) in seen,
          "imported PFX copied to both destinations",
          seconds={ka: round(seen.get(("t8", ka), 0)), kb: round(seen.get(("t8", kb), 0))})

    replica_tags = db.get_certificate(N["t8"]).properties.tags or {}
    check("T8", replica_tags.get("kvsync-origin") == src_name and "kvsync" not in replica_tags,
          "the copy carries kvsync-origin and not the opt-in tag",
          tags=sorted(replica_tags))

    ctx = Context(source_uri=ua, dests=[Dest(kb, ub)], credential=cred)
    res = sync_certificate(N["t8"], ctx, trigger="test")  # a destination copy, offered as if it were a source
    check("T5", bool(res) and res[0]["result"] == "skipped-loop-guard",
          f"loop guard: a copy is never replicated again (function returned {res[0]['result'] if res else res})")

    # ---------------------------------------------------------------------------------------------- T6 and T9
    if not a.skip_timer:
        check("T6", thumb(da, N["t6"]) is None and thumb(db, N["t6"]) is None,
              "the untagged certificate was not copied (skipped-not-opted-in)")

        version = src.get_certificate(N["t6"]).properties.version
        src.update_certificate_properties(N["t6"], version=version, tags={"kvsync": "all"})
        say("T6  opt-in tag added AFTER the event was processed (a tag change fires NO event)")

        ver4 = db.get_certificate(N["t4"]).properties.version
        db.update_certificate_properties(N["t4"], version=ver4, tags={"kvsync-origin": src_name})
        say(f"T9  tagged the unmanaged {N['t4']} in {kb} with kvsync-origin={src_name} (the adoption step)")
        t_tag = time.time()

        say(f"WAIT  for the next timer sweep (up to {a.timer_timeout_min} min)")
        end = time.time() + a.timer_timeout_min * 60
        done6 = done9 = False
        while time.time() < end and not (done6 and done9):
            if not done6 and thumb(da, N["t6"]) == th["t6"] and thumb(db, N["t6"]) == th["t6"]:
                done6 = True
                check("T6", True, f"the timer sweep copied it {(time.time() - t_tag) / 60:.1f} min after tagging (safety net works)",
                      minutes=round((time.time() - t_tag) / 60, 1))
            if not done9 and thumb(db, N["t4"]) == th["t4"]:
                done9 = True
                check("T9", True, f"the next sweep took over the adopted certificate {(time.time() - t_tag) / 60:.1f} min after tagging",
                      minutes=round((time.time() - t_tag) / 60, 1))
            time.sleep(5)
        if not done6:
            check("T6", False, "the timer sweep did not copy the late opt-in in time")
        if not done9:
            check("T9", False, "the timer sweep did not take over the adopted certificate in time")
        if done9:
            versions = list(db.list_properties_of_certificate_versions(N["t4"]))
            cur = db.get_certificate(N["t4"]).properties.tags or {}
            check("T9", len(versions) == 2 and cur.get("kvsync-origin") == src_name and "kvsync-source-version" in cur,
                  "the unmanaged version is still there as an older version (rollback possible); the new version is tagged as a copy",
                  versions=len(versions))

    # ---------------------------------------------------------------------------------------------- CLEAN UP
    if not a.keep:
        for client, label in ((src, "source"), (da, ka), (db, kb)):
            for name in N.values():
                try:
                    client.begin_delete_certificate(name).wait()
                except ResourceNotFoundError:
                    pass
        say("CLEAN  deleted the test certificates from all three vaults (soft-deleted; purge protection may keep the names reserved)")

    verdict = "ALL PASSED" if not failures else "FAILURES: " + "; ".join(failures)
    say(f"=== edge tests done: {verdict} ===")
    if a.evidence:
        Path(a.evidence).write_text(
            json.dumps({"run": a.run, "finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                        "verdict": verdict, "results": results}, indent=2), encoding="utf-8")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
