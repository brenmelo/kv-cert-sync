"""Consumer test: an Application Gateway that serves a certificate straight from a DESTINATION vault.

The gateway lives in the destination's subscription and reads the certificate through its own user-assigned identity, which holds
*Key Vault Secrets User* on that ONE secret and nothing else. It is bound to the VERSIONLESS secret URI, so it can follow new versions.

    terraform -chdir=terraform/poc output -json > outputs.json
    python tests/live/agw.py --outputs outputs.json --cert <certificate name> probe
    python tests/live/agw.py --outputs outputs.json --cert <certificate name> rotate
    python tests/live/agw.py --outputs outputs.json --cert <certificate name> follow --max-hours 5

probe   what does the listener serve, and is it the certificate that is in the destination vault?
rotate  rotate the certificate at the SOURCE (one-shot tag kvrenew-now=1), wait until the destination holds the new version,
        record that the gateway still serves the OLD one (it polls Key Vault only every four hours), then run the documented
        forced refresh (point the listener at the versioned secret id, then back at the versionless one) and time the pickup.
follow  the same rotation, but do NOT force anything: poll the listener every minute and record when the gateway picks the
        new version up by itself. Costs only the hours the gateway stays up.

The TLS handshake is made with verification switched off on purpose: the certificate is signed by a private test CA, so no
client would trust it. Only the identity of the certificate (its SHA-1 thumbprint) is compared, never its trust.
"""
import argparse
import datetime as dt
import hashlib
import json
import shutil
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from azure.core.exceptions import ResourceNotFoundError
from azure.identity import AzureCliCredential
from azure.keyvault.certificates import CertificateClient
from azure.keyvault.secrets import SecretClient
from cryptography import x509

SSL_CERT_NAME = "kv-cert"  # the name the Terraform module gives the certificate on the gateway
SNI = "www.example.test"  # the listener is a basic listener, so any server name gets the same certificate


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%H:%M:%S")


def log(msg: str) -> None:
    print(f"{now()}Z {msg}", flush=True)


def thumb(cert) -> str:
    return cert.properties.x509_thumbprint.hex().upper()


def served(host: str, port: int = 443, timeout: int = 20) -> dict:
    """What a client would receive from the listener: leaf certificate, thumbprint and negotiated TLS version."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=SNI) as tls:
            der = tls.getpeercert(binary_form=True)
            proto = tls.version()
    cert = x509.load_der_x509_certificate(der)
    return {
        "thumbprint": hashlib.sha1(der).hexdigest().upper(),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "tls": proto,
    }


def served_or_none(host: str) -> dict | None:
    try:
        return served(host)
    except (OSError, ssl.SSLError) as exc:
        log(f"    listener not answering yet ({type(exc).__name__}: {exc})")
        return None


def wait(pred, timeout: int, interval: int, what: str):
    t0 = time.time()
    while time.time() - t0 < timeout:
        v = pred()
        if v:
            return v, time.time() - t0
        time.sleep(interval)
    raise TimeoutError(f"timed out after {timeout}s waiting for: {what}")


def az(*args: str) -> str:
    exe = shutil.which("az") or shutil.which("az.cmd")
    r = subprocess.run([exe, *args, "--only-show-errors", "-o", "json"], capture_output=True, text=True, timeout=900)
    if r.returncode != 0:
        raise RuntimeError(f"az {' '.join(args[:3])} failed: {r.stderr.strip()[:600]}")
    return r.stdout


def load(path: str) -> dict:
    out = json.load(open(path, encoding="utf-8-sig"))
    return {k: v.get("value", v) if isinstance(v, dict) and "value" in v else v for k, v in out.items()}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("phase", choices=["probe", "rotate", "follow"])
    ap.add_argument("--max-hours", type=float, default=5.0, help="follow: how long to wait for the gateway's own poll")
    ap.add_argument("--rotate-via", choices=["renewal", "operator"], default="renewal",
                    help="renewal: tag the certificate and let the renewal function do it. operator: create the new version yourself (new CSR, test CA, merge)")
    ap.add_argument("--outputs", required=True)
    ap.add_argument("--cert", required=True, help="certificate name in the consumer (destination b) vault")
    ap.add_argument("--evidence", default="agw-evidence.json")
    a = ap.parse_args()

    out = load(a.outputs)
    gw = out["app_gateway"]
    if not gw:
        print("The stack has no application gateway (enable_app_gateway = false).")
        return 2
    cred = AzureCliCredential(process_timeout=90)
    src = CertificateClient(out["source_vault"]["uri"], cred)
    dst_uri = out["destination_vaults"]["b"]["uri"]
    dst = CertificateClient(dst_uri, cred)
    dst_secrets = SecretClient(dst_uri, cred)
    ev: dict = {"started_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "gateway": gw["name"], "public_ip": gw["public_ip"], "cert": a.cert}
    ok_all = True

    def verdict(label: str, ok: bool, detail: str = "") -> None:
        nonlocal ok_all
        ok_all = ok_all and ok
        print(f"{now()}Z {'PASS' if ok else 'FAIL'}  {label}  {detail}", flush=True)

    state = json.loads(az("network", "application-gateway", "show", "-g", gw["resource_group"], "-n", gw["name"], "--subscription", gw["subscription"]))
    bound = [c.get("keyVaultSecretId") for c in state["sslCertificates"]]
    ev["provisioning_state"] = state["provisioningState"]
    ev["bound_secret_ids"] = bound
    log(f"gateway {gw['name']}  state={state['provisioningState']}  sku={state['sku']['name']}  bound to {bound}")
    verdict("the listener is bound to the VERSIONLESS secret id (so it can follow new versions)", all(b and b.count("/") == 4 for b in bound), str(bound))

    cur = dst.get_certificate(a.cert)
    s0 = wait(lambda: served_or_none(gw["public_ip"]), 300, 15, "the listener to answer on 443")[0]
    ev["before"] = {"destination_thumbprint": thumb(cur), "served": s0}
    log(f"destination vault holds {thumb(cur)[:16]}..  listener serves {s0['thumbprint'][:16]}..  ({s0['tls']}, issuer {s0['issuer']})")
    verdict("the listener serves exactly the certificate that is in the destination vault", s0["thumbprint"] == thumb(cur))

    if a.phase == "probe":
        ev["overall"] = "ALL PASS" if ok_all else "FAILED"
        json.dump(ev, open(a.evidence, "w", encoding="utf-8"), indent=2)
        log(f"evidence written to {a.evidence}; overall: {ev['overall']}")
        return 0 if ok_all else 1

    # ------------------------------------------------------------------ rotate
    first_src = src.get_certificate(a.cert)
    t_issue = time.time()
    if a.rotate_via == "operator":
        # A person (or a pipeline) produces a new version in the source vault: new CSR, signed by the test CA, merged.
        # No renewal function is involved, so its rate limit (3 renewals in 24 hours) cannot get in the way.
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        import live_check

        cur_tags = {k: v for k, v in (first_src.properties.tags or {}).items() if k != "kvrenew-now"}
        pol = first_src.policy
        log(f"rotate at the SOURCE as an operator: new CSR for {pol.subject}, signed by the test CA, merged")
        rc = live_check.cmd_issue(SimpleNamespace(
            source=out["source_vault"]["uri"], name=a.cert, cn=pol.subject.removeprefix("CN="), san=list(pol.san_dns_names or []),
            days=90, age_days=0, tag=[f"{k}={v}" for k, v in cur_tags.items()], non_exportable=False, ca_secret="ca-testca-bundle"))
        if rc != 0:
            raise RuntimeError("the operator rotation failed")
    else:
        log("rotate at the SOURCE: set the one-shot tag kvrenew-now=1 (the renewal function does the rest)")
        tags = dict(first_src.properties.tags or {})
        tags["kvrenew-now"] = "1"
        src.update_certificate_properties(a.cert, tags=tags)
    t0 = time.time()

    def newer():
        try:
            c = dst.get_certificate(a.cert)
        except ResourceNotFoundError:
            return None
        return c if thumb(c) != thumb(cur) else None

    newc, dt_new = wait(newer, 1200, 10, "the new version in the destination vault")
    log(f"destination vault holds the new version {dt_new:.0f}s after the tag was set: {thumb(newc)[:16]}..")
    ev["rotation"] = {"destination_new_after_s": round(dt_new, 1), "new_thumbprint": thumb(newc), "old_thumbprint": thumb(cur)}

    s1 = served(gw["public_ip"])
    log(f"listener right after the vault changed: still serves {s1['thumbprint'][:16]}.. (the gateway polls Key Vault about every four hours)")
    verdict("the gateway has NOT picked the new version up by itself yet (documented four-hour poll)", s1["thumbprint"] == thumb(cur), f"served={s1['thumbprint'][:16]}.. vault={thumb(newc)[:16]}..")
    ev["rotation"]["served_right_after_vault_change"] = s1["thumbprint"]

    if a.phase == "follow":
        t_vault = time.time()
        log(f"follow: nothing is forced; polling the listener every minute for up to {a.max_hours:g} h")
        picked = None
        last_note = 0.0
        while time.time() - t_vault < a.max_hours * 3600:
            s = served_or_none(gw["public_ip"])
            if s and s["thumbprint"] == thumb(newc):
                picked = time.time() - t_vault
                break
            if time.time() - last_note >= 900:
                last_note = time.time()
                log(f"    still serving {(s or {}).get('thumbprint', '?')[:16]}..  {(time.time() - t_vault) / 60:.0f} min after the vault changed")
            time.sleep(60)
        ev["rotation"]["picked_up_by_itself_after_min"] = None if picked is None else round(picked / 60, 1)
        verdict("the gateway picked the new version up by itself", picked is not None,
                f"{picked / 60:.0f} min after the vault changed" if picked is not None else f"not within {a.max_hours:g} h")
        ev["overall"] = "ALL PASS" if ok_all else "FAILED"
        json.dump(ev, open(a.evidence, "w", encoding="utf-8"), indent=2)
        log(f"evidence written to {a.evidence}; overall: {ev['overall']}")
        return 0 if ok_all else 1

    # the forced refresh, exactly as Microsoft documents it for a stalled auto-rotation
    versioned = dst_secrets.get_secret(a.cert).id
    versionless = bound[0]
    log(f"forced refresh 1/2: point the listener at the VERSIONED secret id {versioned.rsplit('/', 1)[-1][:8]}..")
    t1 = time.time()
    az("network", "application-gateway", "ssl-cert", "update", "-g", gw["resource_group"], "--gateway-name", gw["name"], "-n", SSL_CERT_NAME,
       "--key-vault-secret-id", versioned, "--subscription", gw["subscription"])
    log(f"    done in {time.time() - t1:.0f}s")
    log("forced refresh 2/2: restore the VERSIONLESS secret id so that auto-rotation keeps working")
    t2 = time.time()
    az("network", "application-gateway", "ssl-cert", "update", "-g", gw["resource_group"], "--gateway-name", gw["name"], "-n", SSL_CERT_NAME,
       "--key-vault-secret-id", versionless, "--subscription", gw["subscription"])
    log(f"    done in {time.time() - t2:.0f}s")

    s2, dt_pick = wait(lambda: (lambda x: x if x and x["thumbprint"] == thumb(newc) else None)(served_or_none(gw["public_ip"])), 900, 15, "the listener to serve the new certificate")
    log(f"the listener serves the new certificate {time.time() - t1:.0f}s after the forced refresh started: {s2['thumbprint'][:16]}..")
    verdict("after the forced refresh the listener serves the NEW certificate that the sync wrote to the destination", s2["thumbprint"] == thumb(newc))
    after = json.loads(az("network", "application-gateway", "show", "-g", gw["resource_group"], "-n", gw["name"], "--subscription", gw["subscription"]))
    bound_after = [c.get("keyVaultSecretId") for c in after["sslCertificates"]]
    verdict("the listener is bound to the versionless secret id again", bound_after == bound, str(bound_after))
    ev["rotation"].update({"served_after_forced_refresh": s2["thumbprint"], "forced_refresh_total_s": round(time.time() - t1, 1), "bound_after": bound_after,
                           "total_s_since_tag": round(time.time() - t0, 1)})
    ev["overall"] = "ALL PASS" if ok_all else "FAILED"
    json.dump(ev, open(a.evidence, "w", encoding="utf-8"), indent=2)
    log(f"evidence written to {a.evidence}; overall: {ev['overall']}")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
