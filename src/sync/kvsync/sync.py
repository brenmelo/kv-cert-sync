"""Replicate exportable Key Vault certificates from ONE source vault to N destination vaults.

Design rules
  * opt-in per certificate with the tag   kvsync = all | <dest-key>[,<dest-key>...]
  * always converge on the LATEST source version (an event is only a trigger, never the source of truth)
  * idempotent: destination thumbprint == source thumbprint -> nothing to do
  * verified: every copy is re-read and its certificate is compared byte-for-byte with the source (the destination
    identity is deliberately NOT allowed to read private keys back; key equality is proven out-of-band by the test tool)
  * safe: copies carry the tag kvsync-origin and are never replicated again; an unmanaged destination
    certificate with the same name is never overwritten
  * permanent problems are logged and acknowledged; transient problems raise so Event Grid retries
Every outcome is logged as one line  "KVSYNC result=<...> cert=<...> ..."  so it can be queried with KQL.
"""
from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import json
import logging
import os
import threading
from typing import Any, Optional
from urllib.parse import urlparse

from azure.core.exceptions import ResourceNotFoundError
from azure.identity import AzureCliCredential, ManagedIdentityCredential
from azure.keyvault.certificates import (
    CertificateClient,
    CertificateContentType,
    CertificatePolicy,
    KeyCurveName,
    KeyType,
)
from azure.keyvault.secrets import SecretClient
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

log = logging.getLogger("kvsync")

OPT_IN_TAG = "kvsync"
ORIGIN_TAG = "kvsync-origin"


class PermanentSyncError(Exception):
    """Something retrying cannot fix (non-exportable certificate, key/cert mismatch, name collision...)."""


class DestinationError(RuntimeError):
    """One or more destination vaults could not be updated. The others were.

    `failures` is a list of (destination key, exception). Raised AFTER every selected destination has been tried, so a firewall
    rule, a role assignment or an outage at one destination never stops the copy to the rest.
    """

    def __init__(self, failures: list) -> None:
        self.failures = failures
        super().__init__("; ".join(f"dest={k} {type(e).__name__}: {_one_line(e, 200)}" for k, e in failures))


def _one_line(e: BaseException, limit: int = 600) -> str:
    """An exception as one short log line: Azure SDK errors span many lines, which makes a log query hard to read."""
    return " ".join(str(e).split())[:limit] or type(e).__name__


@dataclasses.dataclass(frozen=True)
class Dest:
    key: str
    uri: str


@dataclasses.dataclass
class Material:
    cert: x509.Certificate
    key: Any
    raw: bytes
    content_type: str
    thumbprint: str  # SHA-1 of the DER certificate, upper-case hex (same value Key Vault shows)
    key_id: str  # SHA-256 over the SubjectPublicKeyInfo of the private key's public half


@dataclasses.dataclass
class Context:
    source_uri: str
    dests: list
    credential: Any
    _certs: dict = dataclasses.field(default_factory=dict)
    _secrets: dict = dataclasses.field(default_factory=dict)

    def certs(self, uri: str) -> CertificateClient:
        if uri not in self._certs:
            self._certs[uri] = CertificateClient(uri, self.credential)
        return self._certs[uri]

    def secrets(self, uri: str) -> SecretClient:
        if uri not in self._secrets:
            self._secrets[uri] = SecretClient(uri, self.credential)
        return self._secrets[uri]

    @property
    def source_name(self) -> str:
        return vault_name(self.source_uri)


def vault_name(uri: str) -> str:
    return (urlparse(uri).hostname or uri).split(".")[0]


def parse_event_message(raw: bytes) -> list:
    """Return the Event Grid events carried by one Storage Queue message.

    Event Grid stores the event in the queue as base64-encoded JSON. The Functions host decodes it when
    `extensions.queues.messageEncoding` is `base64` (the default). This also accepts plain JSON, so a changed host
    setting cannot silently break ingestion. (Setting `none` made every message fail to parse and land in the poison
    queue; the 5-minute timer sweep hid that until the queue path was tested on its own.)
    Raises ValueError when the message is neither, so the host retries it and finally poisons it instead of dropping it.
    """
    text = raw.decode("utf-8").strip()
    try:
        body = json.loads(text)
    except ValueError:
        body = None
    if not isinstance(body, (dict, list)):
        body = json.loads(base64.b64decode(text, validate=True).decode("utf-8"))
    events = body if isinstance(body, list) else [body]
    return [e for e in events if isinstance(e, dict)]


def build_context() -> Context:
    client_id = os.environ.get("KVSYNC_CLIENT_ID")
    credential = ManagedIdentityCredential(client_id=client_id) if client_id else AzureCliCredential()
    dests = [Dest(key=d["key"], uri=d["uri"]) for d in json.loads(os.environ["DEST_VAULTS_JSON"])]
    return Context(source_uri=os.environ["SOURCE_VAULT_URI"], dests=dests, credential=credential)


def _emit(level: int, **fields: Any) -> None:
    parts = []
    for k, v in fields.items():
        if v is None:
            continue
        s = str(v)
        parts.append(f'{k}="{s}"' if (" " in s or k == "msg") else f"{k}={s}")
    log.log(level, "KVSYNC " + " ".join(parts))


def _replica_warn_days() -> float:
    """A copy with fewer days left than this is reported (setting REPLICA_WARN_DAYS, default 7)."""
    try:
        return float(os.environ.get("REPLICA_WARN_DAYS", "7"))
    except ValueError:
        return 7.0


def _days_left(m: "Material") -> float:
    return (m.cert.not_valid_after_utc - dt.datetime.now(dt.timezone.utc)).total_seconds() / 86400


def _warn_if_expiring(m: "Material", fields: dict) -> None:
    """The copy is up to date, but is it about to run out?

    A healthy chain renews a certificate long before this threshold, and the copy follows within one sweep, so this line only
    appears when something upstream is stuck (renewal not running, the CA refusing, the source tag removed...). It replaces
    Key Vault's own near-expiry event, which fires 30 days before expiry and cannot be changed: with a 47-day certificate that
    is two weeks BEFORE a healthy renewal, so alerting on it would be noise.
    """
    left, warn = _days_left(m), _replica_warn_days()
    if left < warn:
        _emit(logging.WARNING, result="replica-expiring", days_left=round(left, 1), warn_days=warn, **fields)


# ----------------------------------------------------------------------------- certificate material
def _spki(public_key) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _sha256_hex(data: bytes) -> str:
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize().hex()


def load_material(secret) -> Material:
    """Parse the addressable secret of a Key Vault certificate (PKCS#12 or PEM) and prove cert + key belong together."""
    content_type = (secret.properties.content_type or "").lower()
    value = secret.value or ""
    key = None
    cert = None
    if content_type == "application/x-pkcs12":
        raw = base64.b64decode(value)
        key, cert, _chain = pkcs12.load_key_and_certificates(raw, None)
    elif content_type == "application/x-pem-file":
        raw = value.encode("utf-8")
        certs = x509.load_pem_x509_certificates(raw)
        cert = certs[0] if certs else None
        try:
            key = serialization.load_pem_private_key(raw, password=None)
        except (ValueError, TypeError):
            key = None
    else:
        raise PermanentSyncError(f"unsupported secret content type {content_type!r}")
    if cert is None:
        raise PermanentSyncError("secret holds no certificate")
    if key is None:
        raise PermanentSyncError("secret has no private key (certificate key is not exportable)")
    if _spki(cert.public_key()) != _spki(key.public_key()):
        raise PermanentSyncError("private key does not match the certificate")
    return Material(
        cert=cert,
        key=key,
        raw=raw,
        content_type=content_type,
        thumbprint=cert.fingerprint(hashes.SHA1()).hex().upper(),
        key_id=_sha256_hex(_spki(key.public_key())),
    )


def _import_policy(m: Material) -> CertificatePolicy:
    """Policy for the destination copy, derived from the real key so Key Vault never sees a mismatch."""
    kw: dict = {"exportable": True, "reuse_key": False}
    k = m.key
    if isinstance(k, rsa.RSAPrivateKey):
        kw.update(key_type=KeyType.rsa, key_size=k.key_size)
    elif isinstance(k, ec.EllipticCurvePrivateKey):
        curve = {
            "secp256r1": KeyCurveName.p_256,
            "secp384r1": KeyCurveName.p_384,
            "secp521r1": KeyCurveName.p_521,
        }.get(k.curve.name)
        if curve is None:
            raise PermanentSyncError(f"unsupported EC curve {k.curve.name}")
        kw.update(key_type=KeyType.ec, key_curve_name=curve)
    else:
        raise PermanentSyncError(f"unsupported key type {type(k).__name__}")
    ctype = CertificateContentType.pkcs12 if m.content_type == "application/x-pkcs12" else CertificateContentType.pem
    return CertificatePolicy(issuer_name="Unknown", content_type=ctype, **kw)


def _thumb(props) -> Optional[str]:
    tp = getattr(props, "x509_thumbprint", None)
    return tp.hex().upper() if tp else None


def _select_targets(selector: str, dests: list) -> list:
    sel = selector.strip().lower()
    if sel in ("all", "*", "true", "yes", "1"):
        return list(dests)
    wanted = {s.strip() for s in sel.split(",") if s.strip()}
    unknown = wanted - {d.key for d in dests}
    if unknown:
        _emit(logging.WARNING, result="config-warning", msg=f"tag selects unknown destination(s): {sorted(unknown)}")
    return [d for d in dests if d.key in wanted]


# ----------------------------------------------------------------------------- one certificate
# Two events for the same certificate can arrive together (a new-version event and a near-expiry event were seen at the same
# second in the end-to-end test) and the Functions host runs queue messages on several threads. Without a lock both threads read
# a destination that does not hold the new version yet, and both import it: the destination ends with a duplicate, identical
# version. The lock is per certificate name, so different certificates are still copied in parallel.
#
# It is per process. Two instances of the function app could still overlap; the harm is the same extra identical version, never
# a failure or a wrong certificate, and the next event or sweep finds every destination converged.
_CERT_LOCKS: dict = {}
_CERT_LOCKS_GUARD = threading.Lock()


def _cert_lock(name: str) -> threading.Lock:
    with _CERT_LOCKS_GUARD:
        return _CERT_LOCKS.setdefault(name, threading.Lock())


def sync_certificate(name: str, ctx: Context, *, trigger: str, event_version: Optional[str] = None) -> list:
    """Make every selected destination vault hold the latest version of source certificate `name`.

    One thread at a time works on a given certificate, so overlapping events cannot both import the same version.
    """
    with _cert_lock(name):
        return _sync_certificate(name, ctx, trigger=trigger, event_version=event_version)


def _sync_certificate(name: str, ctx: Context, *, trigger: str, event_version: Optional[str] = None) -> list:
    base = dict(cert=name, trigger=trigger, event_version=event_version)
    src = ctx.certs(ctx.source_uri)

    try:
        cert = src.get_certificate(name)
    except ResourceNotFoundError:
        try:
            op = src.get_certificate_operation(name)
            _emit(logging.INFO, result="skipped-pending", status=op.status, **base)
            return [{"result": "skipped-pending"}]
        except ResourceNotFoundError:
            _emit(logging.WARNING, result="skipped-not-found", **base)
            return [{"result": "skipped-not-found"}]

    if not cert.cer:
        _emit(logging.INFO, result="skipped-pending", **base)
        return [{"result": "skipped-pending"}]

    props = cert.properties
    tags = props.tags or {}
    if ORIGIN_TAG in tags:
        _emit(logging.INFO, result="skipped-loop-guard", src_version=props.version, **base)
        return [{"result": "skipped-loop-guard"}]
    selector = tags.get(OPT_IN_TAG)
    if not selector:
        _emit(logging.INFO, result="skipped-not-opted-in", src_version=props.version, **base)
        return [{"result": "skipped-not-opted-in"}]
    if props.enabled is False:
        _emit(logging.INFO, result="skipped-disabled", src_version=props.version, **base)
        return [{"result": "skipped-disabled"}]

    targets = _select_targets(selector, ctx.dests)
    if not targets:
        _emit(logging.WARNING, result="skipped-no-targets", selector=selector, **base)
        return [{"result": "skipped-no-targets"}]

    try:
        policy = src.get_certificate_policy(name)
        if not policy.exportable:
            raise PermanentSyncError("certificate policy is not exportable (private key cannot be read from the vault)")
        # Read the secret of EXACTLY the version we just inspected, so a rotation in flight cannot mix versions.
        secret = ctx.secrets(ctx.source_uri).get_secret(name, props.version)
        material = load_material(secret)
    except PermanentSyncError as e:
        _emit(logging.ERROR, result="failed-permanent", src_version=props.version, msg=str(e), **base)
        return [{"result": "failed-permanent", "msg": str(e)}]

    src_thumb = _thumb(props)
    if src_thumb and src_thumb != material.thumbprint:
        # certificate and secret disagree -> caught mid-rotation; let the caller retry
        raise RuntimeError(f"source certificate/secret thumbprint mismatch for {name} (rotation in flight?)")

    results: list = []
    failed: list = []
    for dest in targets:
        try:
            results.append(_copy(ctx, dest, name, material, props, tags, base))
        except Exception as e:  # noqa: BLE001  one unreachable destination must not stop the copy to the others
            failed.append((dest.key, e))
    if failed:
        raise DestinationError(failed)
    return results


def _copy(ctx: Context, dest: Dest, name: str, m: Material, props, tags: dict, base: dict) -> dict:
    dcerts = ctx.certs(dest.uri)
    fields = dict(dest=dest.key, thumb=m.thumbprint, src_version=props.version, **base)

    try:
        existing = dcerts.get_certificate(name)
    except ResourceNotFoundError:
        existing = None

    if existing is not None:
        etags = existing.properties.tags or {}
        owner = etags.get(ORIGIN_TAG)
        if owner is None:
            msg = (
                f"destination already holds an unmanaged certificate named {name}; refusing to overwrite "
                f"(to let this sync own it, tag that certificate {ORIGIN_TAG}={ctx.source_name})"
            )
            _emit(logging.ERROR, result="failed-permanent", msg=msg, **fields)
            return {"dest": dest.key, "result": "failed-permanent", "msg": msg}
        if owner != ctx.source_name:
            # a replica made by another source vault: two sources fighting over one name would flip-flop forever
            msg = f"destination certificate {name} is a replica of {owner}, not of {ctx.source_name}; refusing to overwrite"
            _emit(logging.ERROR, result="failed-permanent", msg=msg, **fields)
            return {"dest": dest.key, "result": "failed-permanent", "msg": msg}
        if _thumb(existing.properties) == m.thumbprint:
            _emit(logging.INFO, result="converged-noop", dst_version=existing.properties.version, days_left=round(_days_left(m), 1), **fields)
            _warn_if_expiring(m, fields)
            return {"dest": dest.key, "result": "converged-noop", "thumbprint": m.thumbprint}

    # kvsync is the opt-in marker and kvrenew* are renewal-automation settings: neither belongs on a replica
    out_tags = {k: v for k, v in tags.items() if k != OPT_IN_TAG and not k.startswith("kvrenew")}
    out_tags.update(
        {
            ORIGIN_TAG: ctx.source_name,
            "kvsync-source-version": props.version,
            "kvsync-synced-utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )
    imported = dcerts.import_certificate(name, m.raw, enabled=True, tags=out_tags, policy=_import_policy(m))

    # Prove the copy WITHOUT read access to the destination private key (least privilege: the identity that writes
    # to a destination vault cannot read keys back). The stored certificate must be byte-identical to the source's;
    # the private key travels inside the very same PKCS#12/PEM bytes that were validated against the certificate above.
    stored = dcerts.get_certificate_version(name, imported.properties.version)
    if _thumb(stored.properties) != m.thumbprint or bytes(stored.cer or b"") != m.cert.public_bytes(serialization.Encoding.DER):
        raise RuntimeError(f"verification failed after import into {dest.key}")
    _emit(logging.INFO, result="copied", dst_version=imported.properties.version, verified="cert-bytes-identical", days_left=round(_days_left(m), 1), **fields)
    _warn_if_expiring(m, fields)
    return {"dest": dest.key, "result": "copied", "thumbprint": m.thumbprint, "dst_version": imported.properties.version}


# ----------------------------------------------------------------------------- safety net
def report_failure(cert: str, trigger: str, exc: BaseException, *, result: str = "failed-transient", level: int = logging.ERROR, **more: Any) -> None:
    """Log a failure that is not (yet) a permanent one, in the standard one-line format.

    A DestinationError (some destinations failed, the others were updated) gets one line per destination that failed, with `dest=`.
    """
    for dest, e in getattr(exc, "failures", None) or [(None, exc)]:
        _emit(level, result=result, cert=cert, trigger=trigger, dest=dest, error=type(e).__name__, msg=_one_line(e), **more)


def reconcile(ctx: Context, *, trigger: str = "timer") -> dict:
    """Walk the source vault and converge every opted-in certificate (covers missed events / bad deliveries)."""
    seen = failures = 0
    for p in ctx.certs(ctx.source_uri).list_properties_of_certificates():
        tags = p.tags or {}
        if not p.enabled or not tags.get(OPT_IN_TAG) or ORIGIN_TAG in tags:
            continue
        seen += 1
        try:
            sync_certificate(p.name, ctx, trigger=trigger)
        except Exception as e:  # keep going; report at the end
            failures += 1
            report_failure(p.name, trigger, e)
    _emit(logging.INFO, result="reconcile-complete", trigger=trigger, seen=seen, failures=failures)
    if failures:
        raise RuntimeError(f"{failures} certificate(s) failed to sync")
    return {"seen": seen, "failures": failures}
