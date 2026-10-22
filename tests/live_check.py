"""Live checks against a deployed stack. Use it to prove that a deployment really works end to end.

Run it as an operator who is signed in with `az login` and who holds Key Vault Administrator on the source vault (the
proof-of-concept stack grants that when `operator_object_id` is set). It only ever touches the vaults you name.

  issue    Create a certificate in the SOURCE vault through the CSR flow (issuer "Unknown", exportable key), have the TEST CA
           sign it, and merge it. This is exactly what happens when a public CA signs the request, minus the purchase.
           --age-days back-dates the certificate so that it is already inside the renewal window.
  watch    Print a time-stamped line every time a vault's copy of a certificate changes. Prints the end-to-end latency.
  compare  Compare a certificate across vaults: thumbprint, private-key proof (signs as the source), expiry and tags.
  tag      Set tags on the current version of a certificate.
  versions List the versions of a certificate (thumbprint, created, expires) to see rotations.

The test CA is a secret in the source vault (ca-testca-bundle). It is not publicly trusted and exists only for this test.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "renew"))
sys.path.insert(0, str(ROOT / "src" / "sync"))

from azure.identity import AzureCliCredential  # noqa: E402
from azure.keyvault.certificates import CertificateClient, CertificatePolicy, KeyType  # noqa: E402
from azure.keyvault.secrets import SecretClient  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  # noqa: E402

from kvrenew.ca import CaOrder, LocalTestCaClient  # noqa: E402
from kvsync.sync import load_material  # noqa: E402


def _cred():
    return AzureCliCredential(process_timeout=90)


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%H:%M:%S")


def _tags(items) -> dict:
    out = {}
    for it in items or []:
        k, _, v = it.partition("=")
        out[k] = v
    return out


def _vaults(specs) -> dict:
    out = {}
    for s in specs:
        k, _, uri = s.partition("=")
        out[k] = uri
    return out


# ----------------------------------------------------------------------------- issue
def cmd_issue(a) -> int:
    cred = _cred()
    certs = CertificateClient(a.source, cred)
    secrets = SecretClient(a.source, cred)
    sans = a.san or [a.cn]
    policy = CertificatePolicy(
        issuer_name="Unknown",  # Key Vault only generates the key pair and the CSR; somebody else signs
        subject=f"CN={a.cn}",
        san_dns_names=sans,
        exportable=not a.non_exportable,
        key_type=KeyType.rsa,
        key_size=2048,
        reuse_key=False,
        content_type="application/x-pkcs12",
        validity_in_months=3,
        enhanced_key_usage=["1.3.6.1.5.5.7.3.1"],
        key_usage=["digitalSignature", "keyEncipherment"],
    )
    tags = _tags(a.tag)
    print(f"[{_now()}] creating pending certificate {a.name!r} (CN={a.cn}, SAN={sans}) in {a.source}")
    certs.begin_create_certificate(a.name, policy, enabled=True, tags=tags)  # never .result(): it would wait for the merge
    op = None
    for _ in range(30):
        try:
            op = certs.get_certificate_operation(a.name)
            if op.csr:
                break
        except Exception:  # noqa: BLE001
            pass
        time.sleep(1)
    if op is None or not op.csr:
        print("Key Vault did not return a CSR", file=sys.stderr)
        return 1
    print(f"[{_now()}] Key Vault generated the key pair and returned a CSR ({len(op.csr)} bytes); status={op.status}")

    bundle = json.loads(secrets.get_secret(a.ca_secret).value)
    backdate = dt.timedelta(days=a.age_days)
    ca = LocalTestCaClient(lambda: bundle, days=a.days, clock=lambda: dt.datetime.now(dt.timezone.utc) - backdate)
    chain = ca.fetch_chain(CaOrder(order_id="live-check", ordered_utc="1970-01-01T00:00:00Z"), bytes(op.csr))
    print(f"[{_now()}] test CA signed the CSR (valid {a.days} days, back-dated {a.age_days} days)")

    merged = certs.merge_certificate(a.name, chain, tags=tags)
    print(f"[{_now()}] merged -> version {merged.properties.version}, expires {merged.properties.expires_on:%Y-%m-%d}, "
          f"thumbprint {merged.properties.x509_thumbprint.hex().upper()}")
    return 0


# ----------------------------------------------------------------------------- watch
def cmd_watch(a) -> int:
    cred = _cred()
    clients = {k: CertificateClient(v, cred) for k, v in _vaults(a.vault).items()}
    last: dict = {}
    t0 = time.time()
    want = a.thumb.upper() if a.thumb else None
    print(f"[{_now()}] watching {a.name!r} in {', '.join(clients)} (timeout {a.timeout}s, every {a.interval}s)", flush=True)
    while time.time() - t0 < a.timeout:
        converged = 0
        for k, c in clients.items():
            try:
                p = c.get_certificate(a.name).properties
                thumb = p.x509_thumbprint.hex().upper()
                state = f"version {p.version[:8]}  thumbprint {thumb}  enabled={p.enabled}"
                if want is None or thumb == want:
                    converged += 1
            except Exception as e:  # noqa: BLE001
                state = f"absent ({type(e).__name__})"
            if last.get(k) != state:
                print(f"[{_now()}] +{time.time() - t0:5.1f}s  [{k:8}] {state}", flush=True)
                last[k] = state
        if converged >= a.expect:
            print(f"[{_now()}] {converged} vault(s) hold the expected certificate after {time.time() - t0:.1f}s")
            return 0
        time.sleep(a.interval)
    print(f"[{_now()}] timed out after {a.timeout}s", file=sys.stderr)
    return 2


# ----------------------------------------------------------------------------- compare
def _proof(m, source_public_key) -> str:
    msg = b"kvsync-proof"
    try:
        if isinstance(m.key, rsa.RSAPrivateKey):
            source_public_key.verify(m.key.sign(msg, padding.PKCS1v15(), hashes.SHA256()), msg, padding.PKCS1v15(), hashes.SHA256())
        else:
            source_public_key.verify(m.key.sign(msg, ec.ECDSA(hashes.SHA256())), msg, ec.ECDSA(hashes.SHA256()))
        return "yes"
    except Exception:  # noqa: BLE001
        return "NO"


def cmd_compare(a) -> int:
    cred = _cred()
    rows, source_pub = [], None
    for key, uri in _vaults(a.vault).items():
        certs = CertificateClient(uri, cred)
        try:
            c = certs.get_certificate(a.name)
        except Exception as e:  # noqa: BLE001
            rows.append((key, "-", "-", "-", "-", "-", f"MISSING ({type(e).__name__})"))
            continue
        m = load_material(SecretClient(uri, cred).get_secret(a.name, c.properties.version))
        source_pub = source_pub or m.cert.public_key()
        t = c.properties.tags or {}
        rows.append((key, c.properties.version[:8], m.thumbprint, m.key_id[:16], _proof(m, source_pub), f"{m.cert.not_valid_after_utc:%Y-%m-%d}",
                     f"origin={t.get('kvsync-origin', '-')} src_ver={str(t.get('kvsync-source-version', '-'))[:8]}"))
    hdr = ("vault", "version", "SHA-1 thumbprint", "private-key id", "signs-as-source", "expires", "tags")
    widths = [max(len(str(r[i])) for r in rows + [hdr]) for i in range(len(hdr))]
    for r in [hdr] + rows:
        print("  ".join(str(v).ljust(widths[i]) for i, v in enumerate(r)))
    ok = [r for r in rows if not r[6].startswith("MISSING")]
    same_cert = len({r[2] for r in ok}) == 1 and len(ok) == len(rows)
    same_key = len({r[3] for r in ok}) == 1 and all(r[4] == "yes" for r in ok)
    print(f"\nidentical thumbprint in all {len(rows)} vault(s): {same_cert}   |   same private key everywhere (sign/verify proof): {same_key}")
    return 0 if (same_cert and same_key) else 1


# ----------------------------------------------------------------------------- tag / versions
def cmd_tag(a) -> int:
    certs = CertificateClient(a.vault, _cred())
    cur = certs.get_certificate(a.name)
    tags = dict(cur.properties.tags or {})
    tags.update(_tags(a.tags))
    for k in a.remove or []:
        tags.pop(k, None)
    certs.update_certificate_properties(a.name, cur.properties.version, tags=tags)
    print(f"[{_now()}] tags on {a.name} ({cur.properties.version[:8]}): {tags}")
    return 0


def cmd_versions(a) -> int:
    certs = CertificateClient(a.vault, _cred())
    rows = sorted(certs.list_properties_of_certificate_versions(a.name), key=lambda p: p.created_on)
    for p in rows:
        t = p.tags or {}
        print(f"{p.created_on:%Y-%m-%d %H:%M:%S}  {p.version[:8]}  thumbprint {p.x509_thumbprint.hex().upper() if p.x509_thumbprint else '-':40}  "
              f"valid {p.not_before:%Y-%m-%d}..{p.expires_on:%Y-%m-%d}  enabled={p.enabled}  tags={ {k: v for k, v in t.items() if k.startswith('kv')} }")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("issue")
    s.add_argument("--source", required=True, help="https://<source-vault>.vault.azure.net/")
    s.add_argument("--name", required=True)
    s.add_argument("--cn", required=True)
    s.add_argument("--san", action="append", help="repeat for several names (default: the common name)")
    s.add_argument("--days", type=int, default=90)
    s.add_argument("--age-days", type=int, default=0, help="back-date the certificate by this many days")
    s.add_argument("--tag", action="append", help="k=v, repeat for several (for example kvsync=all kvrenew=on)")
    s.add_argument("--non-exportable", action="store_true", help="negative test: the sync must refuse this one")
    s.add_argument("--ca-secret", default="ca-testca-bundle")
    s.set_defaults(fn=cmd_issue)

    s = sub.add_parser("watch")
    s.add_argument("--name", required=True)
    s.add_argument("--vault", action="append", required=True, help="key=https://<vault>.vault.azure.net/")
    s.add_argument("--thumb")
    s.add_argument("--expect", type=int, default=3)
    s.add_argument("--timeout", type=int, default=300)
    s.add_argument("--interval", type=float, default=2.0)
    s.set_defaults(fn=cmd_watch)

    s = sub.add_parser("compare")
    s.add_argument("--name", required=True)
    s.add_argument("--vault", action="append", required=True)
    s.set_defaults(fn=cmd_compare)

    s = sub.add_parser("tag")
    s.add_argument("--vault", required=True)
    s.add_argument("--name", required=True)
    s.add_argument("tags", nargs="*", help="k=v")
    s.add_argument("--remove", action="append")
    s.set_defaults(fn=cmd_tag)

    s = sub.add_parser("versions")
    s.add_argument("--vault", required=True)
    s.add_argument("--name", required=True)
    s.set_defaults(fn=cmd_versions)

    a = p.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
