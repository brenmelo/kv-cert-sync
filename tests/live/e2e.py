"""Live end-to-end test of a deployed kv-cert-sync stack (the Terraform proof of concept).

It drives the stack exactly the way an application team would and measures what happens. Nothing is faked: the certificate is
requested in the SOURCE vault, the renewal function orders and merges it (with the private test CA that stands in for DigiCert),
and the sync function copies it to every destination vault.

    terraform -chdir=terraform/poc output -json > outputs.json
    python tests/live/e2e.py --outputs outputs.json --evidence evidence.json

Scenarios
  R1  first issuance   operator creates a PENDING request (issuer Unknown) -> renewal function orders + merges -> sync copies
  R2  forced rotation  one-shot tag kvrenew-now=1 -> new version, NEW key -> synced; old versions stay; the tag is NOT copied forward
  R3  idempotency      nothing happens when nothing changed (no new versions anywhere)
  R4  not opted in     a pending request WITHOUT the kvrenew tag is left alone and is never copied (runs during the R3 quiet period)
Uses `az login` credentials (the operator needs Key Vault Administrator on the vaults, which the proof of concept grants).
"""
import argparse
import datetime as dt
import json
import sys
import time

from azure.core.exceptions import ResourceNotFoundError
from azure.identity import AzureCliCredential
from azure.keyvault.certificates import CertificateClient, CertificateContentType, CertificatePolicy
from cryptography import x509


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%H:%M:%S")


def log(msg: str) -> None:
    print(f"{now()}Z {msg}", flush=True)


def thumb(cert) -> str:
    return cert.properties.x509_thumbprint.hex().upper()


def pub_n(cert) -> int:
    return x509.load_der_x509_certificate(bytes(cert.cer)).public_key().public_numbers().n


def get(client: CertificateClient, name: str):
    """The latest MERGED certificate, or None. While a CSR is pending, Key Vault already returns the pending version
    (no certificate bytes yet), which must not count as issued."""
    try:
        c = client.get_certificate(name)
    except ResourceNotFoundError:
        return None
    return c if c.cer else None


def wait(pred, timeout: int, interval: int, what: str):
    t0 = time.time()
    while time.time() - t0 < timeout:
        v = pred()
        if v:
            return v, time.time() - t0
        time.sleep(interval)
    raise TimeoutError(f"timed out after {timeout}s waiting for: {what}")


def versions(client: CertificateClient, name: str) -> int:
    try:
        return sum(1 for _ in client.list_properties_of_certificate_versions(name))
    except ResourceNotFoundError:
        return 0


def exists_anywhere(client: CertificateClient, name: str) -> bool:
    """True when the name is taken: a live certificate, a pending request, or a soft-deleted one (the name stays reserved)."""
    for probe in (client.get_certificate, client.get_deleted_certificate):
        try:
            probe(name)
            return True
        except ResourceNotFoundError:
            pass
    return False


def request_pending(client: CertificateClient, name: str, tags: dict, cn: str, sans: list) -> None:
    """What an application team does: ask the SOURCE vault for a certificate that a CA outside Key Vault will sign."""
    policy = CertificatePolicy(
        issuer_name="Unknown",  # CSR mode: Key Vault makes the key + CSR and waits for the signed certificate to be merged
        subject=f"CN={cn}",
        san_dns_names=sans,
        exportable=True,
        key_type="RSA",
        key_size=2048,
        reuse_key=False,
        content_type=CertificateContentType.pkcs12,
        validity_in_months=12,
    )
    client.begin_create_certificate(name, policy, tags=tags)  # do NOT wait for it: it completes only when merged


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--outputs", required=True, help="output of `terraform output -json`")
    ap.add_argument("--name", default="e2e-" + dt.datetime.now(dt.timezone.utc).strftime("%d%H%M%S"), help="certificate name; must be unused in every vault")
    ap.add_argument("--cn", default="*.example.com")
    ap.add_argument("--san", nargs="*", default=["*.example.com", "example.com"])
    ap.add_argument("--timeout", type=int, default=900, help="seconds per scenario")
    ap.add_argument("--idempotency-minutes", type=int, default=11)
    ap.add_argument("--skip", nargs="*", default=[], choices=["R1", "R2", "R3", "R4"])
    ap.add_argument("--evidence", default="evidence.json")
    a = ap.parse_args()

    out = json.load(open(a.outputs, encoding="utf-8-sig"))
    out = {k: v.get("value", v) if isinstance(v, dict) and "value" in v else v for k, v in out.items()}
    cred = AzureCliCredential(process_timeout=90)
    src = CertificateClient(out["source_vault"]["uri"], cred)
    dests = {k: CertificateClient(v["uri"], cred) for k, v in out["destination_vaults"].items()}
    ev: dict = {"started_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "name": a.name, "scenarios": {}}
    ok_all = True

    def verdict(label: str, ok: bool, detail: str = "") -> None:
        nonlocal ok_all
        ok_all &= ok
        log(f"{'PASS' if ok else 'FAIL'}  {label}  {detail}")

    name = a.name
    taken = [k for k, cl in {"source": src, **dests}.items() if exists_anywhere(cl, name) or exists_anywhere(cl, f"{name}-notoptedin")]
    if taken:
        log(f"ABORT: '{name}' (or '{name}-notoptedin') already exists in: {taken}. Pick another --name; a used name would give a false pass.")
        return 2

    # ------------------------------------------------------------------ R1
    if "R1" not in a.skip:
        log(f"R1  request '{name}' in the source vault (pending, issuer Unknown, tags kvsync=all kvrenew=on)")
        t_req = time.time()
        request_pending(src, name, {"kvsync": "all", "kvrenew": "on", "app": "demo"}, a.cn, a.san)
        op = src.get_certificate_operation(name)
        log(f"    pending request created, status={op.status}; waiting for the renewal function to order + merge")
        c, dt_merge = wait(lambda: get(src, name), a.timeout, 10, "certificate merged in the source vault")
        log(f"    merged in the source vault after {dt_merge:.0f}s  thumb={thumb(c)[:16]}..")
        copies = {}
        for k, cl in dests.items():
            d, dt_copy = wait(lambda cl=cl: (lambda x: x if x and thumb(x) == thumb(c) else None)(get(cl, name)), 300, 4, f"copy in destination {k}")
            copies[k] = (d, dt_copy)
            log(f"    copied to destination {k} {dt_copy:.0f}s after the merge  tags={sorted(d.properties.tags or {})}")
        issuer = x509.load_der_x509_certificate(bytes(c.cer)).issuer.rfc4514_string()
        verdict("R1 source certificate is issued by the CA", "Test Root CA" in issuer, issuer)
        verdict("R1 all destinations hold the same certificate", all(thumb(d) == thumb(c) for d, _ in copies.values()))
        verdict("R1 destination keeps the SAME private key (same public modulus)", all(pub_n(d) == pub_n(c) for d, _ in copies.values()))
        verdict(
            "R1 replicas carry kvsync-origin and do NOT carry kvsync / kvrenew",
            all("kvsync-origin" in (d.properties.tags or {}) and "kvsync" not in (d.properties.tags or {}) and "kvrenew" not in (d.properties.tags or {}) for d, _ in copies.values()),
        )
        ev["scenarios"]["R1"] = {
            "request_to_merge_s": round(time.time() - t_req - 0, 1),
            "merge_wait_s": round(dt_merge, 1),
            "copy_after_merge_s": {k: round(v[1], 1) for k, v in copies.items()},
            "thumb": thumb(c),
            "version": c.properties.version,
            "issuer": issuer,
            "not_after": c.properties.expires_on.isoformat(),
        }
        first = c

    # ------------------------------------------------------------------ R2
    if "R2" not in a.skip:
        first = first if "R1" not in a.skip else src.get_certificate(name)
        log("R2  rotate now: set the one-shot tag kvrenew-now=1 on the certificate (what an operator does after a key compromise)")
        tags = dict(first.properties.tags or {})
        tags["kvrenew-now"] = "1"
        src.update_certificate_properties(name, tags=tags)
        t0 = time.time()
        newc, dt_new = wait(lambda: (lambda x: x if x and x.properties.version != first.properties.version else None)(get(src, name)), a.timeout, 10, "a new version in the source vault")
        log(f"    new version merged {dt_new:.0f}s after the tag was set  thumb={thumb(newc)[:16]}..")
        copies = {}
        for k, cl in dests.items():
            d, dt_copy = wait(lambda cl=cl: (lambda x: x if x and thumb(x) == thumb(newc) else None)(get(cl, name)), 300, 4, f"new version in destination {k}")
            copies[k] = (d, dt_copy)
            log(f"    destination {k} serves the new version {dt_copy:.0f}s after the merge; versions kept there: {versions(dests[k], name)}")
        verdict("R2 the rotation created a NEW key (public key differs)", pub_n(newc) != pub_n(first))
        verdict("R2 thumbprint changed and every destination followed", all(thumb(d) == thumb(newc) for d, _ in copies.values()) and thumb(newc) != thumb(first))
        verdict("R2 destinations still hold the previous version (rollback is possible)", all(versions(cl, name) >= 2 for cl in dests.values()))
        verdict("R2 the one-shot tag is NOT on the new version (no rotation loop)", "kvrenew-now" not in (newc.properties.tags or {}), str(sorted(newc.properties.tags or {})))
        ev["scenarios"]["R2"] = {
            "rotation_after_tag_s": round(time.time() - t0, 1),
            "new_version_wait_s": round(dt_new, 1),
            "copy_after_merge_s": {k: round(v[1], 1) for k, v in copies.items()},
            "old_thumb": thumb(first),
            "new_thumb": thumb(newc),
            "versions_in_destinations": {k: versions(cl, name) for k, cl in dests.items()},
        }

    # ------------------------------------------------------------------ R3 + R4 (one shared quiet period)
    other = f"{name}-notoptedin"
    quiet = "R3" not in a.skip or "R4" not in a.skip
    if quiet:
        before = {"src": versions(src, name), **{k: versions(cl, name) for k, cl in dests.items()}}
        if "R4" not in a.skip:
            log(f"R4  request '{other}' WITHOUT the kvrenew tag: it must stay pending and must never be copied")
            request_pending(src, other, {"app": "demo"}, "not-opted-in.example.com", ["not-opted-in.example.com"])
        log(f"R3  idempotency: wait {a.idempotency_minutes} min (two timer sweeps of each function); version counts now {before}")
        time.sleep(a.idempotency_minutes * 60)
    if "R3" not in a.skip:
        after = {"src": versions(src, name), **{k: versions(cl, name) for k, cl in dests.items()}}
        verdict("R3 no new versions anywhere after two sweeps with nothing changed", before == after, f"before={before} after={after}")
        ev["scenarios"]["R3"] = {"before": before, "after": after}
    if "R4" not in a.skip:
        op = src.get_certificate_operation(other)
        verdict("R4 un-tagged pending request is untouched by the renewal function", op.status == "inProgress", f"status={op.status}")
        verdict("R4 nothing was copied", all(get(cl, other) is None for cl in dests.values()))
        try:
            src.delete_certificate_operation(other)
            src.begin_delete_certificate(other).wait()
        except Exception as e:  # noqa: BLE001
            log(f"    cleanup of {other}: {type(e).__name__}")
        ev["scenarios"]["R4"] = {"status": op.status}

    ev["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    ev["all_passed"] = ok_all
    json.dump(ev, open(a.evidence, "w", encoding="utf-8"), indent=2, default=str)
    log(f"evidence written to {a.evidence}; overall: {'ALL PASS' if ok_all else 'FAILURES'}")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
