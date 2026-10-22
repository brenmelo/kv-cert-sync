"""Renew Key Vault certificates whose issuer is "Unknown" (CSR mode, external CA such as DigiCert).

Key Vault never contacts such a CA, so nothing happens after a pending version is created. This module does the part Key
Vault does not:

    due?  ->  new pending version (new key, CSR)  ->  order / reissue at the CA  ->  poll  ->  verify  ->  merge the chain

After the merge Key Vault publishes CertificateNewVersionCreated and the kvsync function copies the certificate to the
destination vaults. This module never touches a destination vault, and never exports a private key.

Opt-in per certificate with the tag  kvrenew = on  (optional  kvrenew-days = <n>  overrides the renewal window).
Every outcome is logged as one line  "KVRENEW result=<...> cert=<...> ..."  so it can be queried with KQL.
Safe to run concurrently and repeatedly: a per-certificate lease serialises runs, and the order is recorded before the
next step, so a restart resumes instead of ordering again.
"""
from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import hashlib
import json
import logging
import os
import time
from typing import Any, Callable, Optional

from azure.core.exceptions import ResourceNotFoundError
from azure.keyvault.certificates import CertificatePolicy
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .ca import CaOrder, CaPermanentError, CaTransientError, make_ca, order_chain, parse_certs, spki_sha256
from .state import StateConflict

log = logging.getLogger("kvrenew")

OPT_IN_TAG = "kvrenew"
DAYS_TAG = "kvrenew-days"
FORCE_TAG = "kvrenew-now"  # one-shot: rotate this certificate on the next sweep (key compromise, drills). Never copied to the new version.
ORDER_TAG = "kvrenew-order-id"  # seeds the CA order to REISSUE the first time (an existing DigiCert order the customer owns)
ORIGIN_TAG = "kvsync-origin"  # a synced replica is never renewed here
DUE_SLACK_DAYS = 0.05  # the near-expiry event fires AT the window edge; do not lose a race by a few minutes


class PermanentRenewError(Exception):
    """Something retrying cannot fix (rejected order, chain for a different key, ...)."""


@dataclasses.dataclass
class Settings:
    days_before_expiry: int = 30
    min_age_hours: float = 24.0
    max_renewals_24h: int = 3
    poll_seconds: int = 90
    poll_interval: int = 10
    max_wait_hours: int = 72
    lease_minutes: int = 10

    @classmethod
    def from_env(cls, env=os.environ) -> "Settings":
        d = cls()
        return cls(
            days_before_expiry=int(env.get("RENEW_DAYS_BEFORE_EXPIRY", d.days_before_expiry)),
            min_age_hours=float(env.get("RENEW_MIN_AGE_HOURS", d.min_age_hours)),
            max_renewals_24h=int(env.get("RENEW_MAX_PER_24H", d.max_renewals_24h)),
            poll_seconds=int(env.get("RENEW_POLL_SECONDS", d.poll_seconds)),
            poll_interval=int(env.get("RENEW_POLL_INTERVAL", d.poll_interval)),
            max_wait_hours=int(env.get("RENEW_MAX_WAIT_HOURS", d.max_wait_hours)),
        )


@dataclasses.dataclass
class Context:
    certs: Any  # azure.keyvault.certificates.CertificateClient (or a fake)
    ca: Any
    store: Any
    settings: Settings = dataclasses.field(default_factory=Settings)
    now: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.timezone.utc)
    sleep: Callable[[float], None] = time.sleep


def build_context(env=os.environ) -> Context:
    from azure.identity import AzureCliCredential, ManagedIdentityCredential
    from azure.keyvault.certificates import CertificateClient
    from azure.keyvault.secrets import SecretClient

    from .state import TableStore

    client_id = env.get("KVRENEW_CLIENT_ID")
    cred = ManagedIdentityCredential(client_id=client_id) if client_id else AzureCliCredential()
    src = env["SOURCE_VAULT_URI"]
    secrets = SecretClient(src, cred)
    ca = make_ca(env.get("CA_PROVIDER", "digicert"), dict(env), lambda n: secrets.get_secret(n).value)
    store = TableStore(env["STATE_TABLE_ENDPOINT"], env.get("STATE_TABLE_NAME", "kvrenew"), cred)
    return Context(certs=CertificateClient(src, cred), ca=ca, store=store, settings=Settings.from_env(env))


def parse_event_message(raw: bytes) -> list:
    """Return the Event Grid events carried by one Storage Queue message (same contract as kvsync.sync.parse_event_message).

    Event Grid stores the event in the queue as base64-encoded JSON. The Functions host decodes it when
    `extensions.queues.messageEncoding` is `base64` (the default). This also accepts plain JSON, so a changed host
    setting cannot silently break ingestion. Raises ValueError when the message is neither, so the host retries it and
    finally poisons it instead of dropping it.
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


# ----------------------------------------------------------------------------- logging
def _emit(level: int, **fields: Any) -> None:
    parts = []
    for k, v in fields.items():
        if v is None:
            continue
        s = str(v)
        parts.append(f'{k}="{s}"' if (" " in s or k == "msg") else f"{k}={s}")
    log.log(level, "KVRENEW " + " ".join(parts))


def _done(result: str, base: dict, level: int = logging.INFO, **more: Any) -> dict:
    out = {"result": result, **base, **more}
    _emit(level, **out)
    return out


# ----------------------------------------------------------------------------- lease + state
def _iso(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(s: Optional[str]) -> Optional[dt.datetime]:
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc) if s else None


class _Lease:
    def __init__(self, ctx: Context, name: str, data: dict, etag: str) -> None:
        self.ctx, self.name, self.data, self.etag = ctx, name, data, etag

    def save(self) -> None:
        self.etag = self.ctx.store.put(self.name, self.data, self.etag)

    def release(self) -> None:
        self.data["lease_until"] = None
        try:
            self.save()
        except StateConflict:
            pass  # the lease simply expires


def _acquire(ctx: Context, name: str) -> Optional[_Lease]:
    data, etag = ctx.store.get(name)
    data = data or {}
    now = ctx.now()
    until = _parse(data.get("lease_until"))
    if until and until > now:
        return None
    data["lease_until"] = _iso(now + dt.timedelta(minutes=ctx.settings.lease_minutes))
    try:
        etag = ctx.store.put(name, data, etag)
    except StateConflict:
        return None
    return _Lease(ctx, name, data, etag)


# ----------------------------------------------------------------------------- Key Vault reads
def _lookup(ctx: Context, name: str):
    """(properties, certificate-or-None). A certificate that has never been issued exists only as a pending operation."""
    try:
        cert = ctx.certs.get_certificate(name)
        return cert.properties, cert
    except ResourceNotFoundError:
        pass
    for p in ctx.certs.list_properties_of_certificates(include_pending=True):
        if p.name == name:
            return p, None
    return None, None


def _operation(ctx: Context, name: str):
    try:
        return ctx.certs.get_certificate_operation(name)
    except ResourceNotFoundError:
        return None


def _in_progress(op) -> bool:
    return op is not None and (op.status or "").lower() == "inprogress"


# ----------------------------------------------------------------------------- public entry points
def renew_certificate(name: str, ctx: Context, *, trigger: str) -> dict:
    base = {"cert": name, "trigger": trigger}
    lease = _acquire(ctx, name)
    if lease is None:
        return _done("busy", base)
    try:
        return _process(name, ctx, base, lease)
    except CaPermanentError as e:
        return _fail(lease, base, str(e))
    except PermanentRenewError as e:
        return _fail(lease, base, str(e))
    finally:
        lease.release()


def one_line(e: BaseException) -> str:
    """An exception as one short log line: Azure SDK errors span many lines, which makes a log query hard to read."""
    return " ".join(str(e).split())[:600] or type(e).__name__


def reconcile_renewals(ctx: Context, *, trigger: str = "timer") -> dict:
    """Visit every opted-in certificate. Failures are collected and raised at the end so the host sees them."""
    summary: dict = {}
    transient: list = []
    for p in ctx.certs.list_properties_of_certificates(include_pending=True):
        tags = p.tags or {}
        if not _opted_in(tags) or ORIGIN_TAG in tags:
            continue
        try:
            r = renew_certificate(p.name, ctx, trigger=trigger)
            summary[r["result"]] = summary.get(r["result"], 0) + 1
        except Exception as e:  # noqa: BLE001  a CA outage, a Key Vault 403, a storage error: one certificate must not stop the sweep for the others
            transient.append(f"{p.name}: {one_line(e)}")
            _emit(logging.ERROR, result="failed-transient", cert=p.name, trigger=trigger, msg=one_line(e), error=type(e).__name__)
    _emit(logging.INFO, result="reconcile-complete", trigger=trigger, **{k.replace("-", "_"): v for k, v in summary.items()}, failures=len(transient))
    if transient:
        raise CaTransientError("; ".join(transient))
    return summary


def _opted_in(tags: dict) -> bool:
    return str(tags.get(OPT_IN_TAG, "")).strip().lower() in ("on", "true", "1", "yes")


# ----------------------------------------------------------------------------- the state machine
def _fail(lease: _Lease, base: dict, msg: str) -> dict:
    lease.data["status"] = "failed"
    lease.data["last_detail"] = msg[:300]
    try:
        lease.save()
    except StateConflict:
        pass
    return _done("failed-permanent", base, logging.ERROR, msg=msg)


def _threshold_days(tags: dict, props, settings: Settings) -> float:
    days = settings.days_before_expiry
    if tags.get(DAYS_TAG):
        days = float(tags[DAYS_TAG])
    if props.not_before and props.expires_on:
        days = min(days, (props.expires_on - props.not_before).total_seconds() / 86400 / 3)
    return days


def _process(name: str, ctx: Context, base: dict, lease: _Lease) -> dict:
    props, cert = _lookup(ctx, name)
    if props is None:
        return _done("not-found", base)
    tags = dict(props.tags or {})
    if not _opted_in(tags):
        return _done("not-opted-in", base)
    if ORIGIN_TAG in tags:
        return _done("skipped-replica", base)
    forced = bool(tags.pop(FORCE_TAG, None))  # popped, so neither the pending request nor the merged version can ever carry it

    op = _operation(ctx, name)
    if _in_progress(op):
        return _fulfil(name, ctx, base, lease, op, tags)
    if cert is None:
        return _done("nothing-to-renew", base, msg="no current version and no pending request")

    now = ctx.now()
    left = (cert.properties.expires_on - now).total_seconds() / 86400
    threshold = _threshold_days(tags, cert.properties, ctx.settings)
    if not forced and left > threshold + DUE_SLACK_DAYS:
        return _done("not-due", base, days_left=round(left, 1), window_days=round(threshold, 1))
    created = cert.properties.created_on
    if not forced and created and (now - created).total_seconds() < ctx.settings.min_age_hours * 3600:
        return _done("skipped-too-new", base, level=logging.WARNING, msg="current version is newer than RENEW_MIN_AGE_HOURS; not renewing again")
    recent = [t for t in lease.data.get("history", []) if now - _parse(t) < dt.timedelta(hours=24)]
    lease.data["history"] = recent
    if len(recent) >= ctx.settings.max_renewals_24h:
        return _done("blocked-rate-limit", base, logging.ERROR, msg=f"{len(recent)} renewals started in 24h; a person needs to look at this")

    started = _start(ctx, name, cert, tags)
    if started is None:
        return _done("skipped-managed-issuer", base, msg="issuer is not Unknown; Key Vault renews this one itself")
    recent.append(_iso(now))
    lease.data["history"] = recent
    lease.data["status"] = "started"
    lease.save()
    _emit(logging.INFO, result="started", **base, days_left=round(left, 1), forced="true" if forced else None)
    op = _operation(ctx, name)
    if not _in_progress(op):
        raise CaTransientError("the pending version was created but its operation is not visible yet")
    return _fulfil(name, ctx, base, lease, op, tags)


def _start(ctx: Context, name: str, cert, tags: dict):
    pol = cert.policy
    if pol is None or (pol.issuer_name or "").lower() != "unknown":
        return None
    new_policy = CertificatePolicy(
        issuer_name="Unknown",
        exportable=pol.exportable,
        key_type=pol.key_type,
        key_size=pol.key_size,
        key_curve_name=pol.key_curve_name,
        reuse_key=False,  # a new key for every renewal
        content_type=pol.content_type,
        subject=pol.subject,
        san_dns_names=pol.san_dns_names,
        san_emails=pol.san_emails,
        san_user_principal_names=pol.san_user_principal_names,
        key_usage=pol.key_usage,
        enhanced_key_usage=pol.enhanced_key_usage,
        validity_in_months=pol.validity_in_months,
        lifetime_actions=pol.lifetime_actions,
    )
    # No .result(): with an Unknown issuer the poller would wait until somebody merges a certificate.
    ctx.certs.begin_create_certificate(name, new_policy, enabled=True, tags=tags)
    return True


def _csr_hash(csr_der: bytes) -> str:
    return hashlib.sha256(csr_der).hexdigest()


def _fulfil(name: str, ctx: Context, base: dict, lease: _Lease, op, tags: dict) -> dict:
    s = ctx.settings
    csr = bytes(op.csr)
    h = _csr_hash(csr)
    d = lease.data
    if d.get("csr_sha256") != h:
        previous = d.get("order_id") or (tags.get(ORDER_TAG) or None)
        order = ctx.ca.submit(csr, previous)
        d.update(
            order_id=order.order_id, order_extra=order.extra, csr_sha256=h, ordered_utc=order.ordered_utc,
            status="ordered", last_detail="",
        )
        lease.save()
        _emit(logging.INFO, result="ordered", **base, order=order.order_id, kind=order.extra.get("kind", "-"))
    order = CaOrder(order_id=d["order_id"], ordered_utc=d["ordered_utc"], extra=d.get("order_extra") or {})
    if d.get("status") == "failed" and d.get("csr_sha256") == h:
        return _done("failed-permanent", base, logging.ERROR, order=order.order_id, msg=d.get("last_detail") or "order failed earlier; delete the pending request to start over")

    deadline = ctx.now() + dt.timedelta(seconds=s.poll_seconds)
    while True:
        st = ctx.ca.status(order)
        if st.state == "failed":
            raise PermanentRenewError(f"CA order {order.order_id} failed: {st.detail}")
        if st.state == "issued":
            break
        if ctx.now() >= deadline:
            waited = (ctx.now() - _parse(order.ordered_utc)).total_seconds() / 3600
            level = logging.WARNING if waited > s.max_wait_hours else logging.INFO
            return _done("waiting", base, level, order=order.order_id, detail=st.detail, waited_hours=round(waited, 2))
        ctx.sleep(s.poll_interval)

    chain = _verified_chain(ctx.ca.fetch_chain(order, csr), csr, ctx.now())
    merged = ctx.certs.merge_certificate(name, chain, tags=tags)
    d.update(status="merged", csr_sha256=None, merged_utc=_iso(ctx.now()), last_detail="")
    lease.save()
    return _done("merged", base, order=order.order_id, version=merged.properties.version, expires=_iso(merged.properties.expires_on))


def _verified_chain(chain_der: list, csr_der: bytes, now: dt.datetime) -> list:
    """Refuse to merge anything that is not exactly the certificate we asked for."""
    csr = x509.load_der_x509_csr(csr_der)
    certs = order_chain([x509.load_der_x509_certificate(c) for c in chain_der], csr.public_key())
    leaf = certs[0]
    if spki_sha256(leaf.public_key()) != spki_sha256(csr.public_key()):
        raise PermanentRenewError("the certificate does not belong to the key Key Vault generated")
    try:
        want = set(n.lower() for n in csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
        have = set(n.lower() for n in leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        want, have = set(), set()
    if not want <= have:
        raise PermanentRenewError(f"the certificate is missing requested names: {sorted(want - have)}")
    if leaf.not_valid_after_utc <= now + dt.timedelta(hours=1):
        raise PermanentRenewError("the certificate is already (nearly) expired")
    if leaf.not_valid_before_utc > now + dt.timedelta(minutes=15):
        raise PermanentRenewError("the certificate is not valid yet")
    return [c.public_bytes(serialization.Encoding.DER) for c in certs]
