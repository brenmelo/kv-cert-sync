"""Certificate-authority clients for the renewal function.

A CaClient turns the CSR that Key Vault generated (the private key never leaves Key Vault) into a signed chain.

    submit(csr_der, previous_order_id) -> CaOrder      place an order (or a reissue) at the CA
    status(order)                      -> CaStatus     pending | issued | failed
    fetch_chain(order, csr_der)        -> [DER, ...]   leaf first

Providers
    digicert  DigiCert CertCentral Services API (REST).
    testca    A private test CA whose key lives in a Key Vault secret. POC ONLY: it proves the automation end to end at
              no cost, and must never be used for a certificate that real clients have to trust.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import logging
import uuid
from typing import Callable, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

log = logging.getLogger("kvrenew")


class CaTransientError(Exception):
    """Network error, 429 or 5xx: try again on the next tick."""


class CaPermanentError(Exception):
    """The CA refused the request (bad product, rejected order, ...): a person has to look at it."""


@dataclasses.dataclass
class CaOrder:
    order_id: str
    ordered_utc: str
    extra: dict = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class CaStatus:
    state: str  # "pending" | "issued" | "failed"
    detail: str = ""
    certificate_id: Optional[str] = None


# ----------------------------------------------------------------------------- helpers
def spki_sha256(public_key) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def csr_names(csr_der: bytes):
    """(common name, [dns names]) from the CSR Key Vault generated."""
    csr = x509.load_der_x509_csr(csr_der)
    cn = next((a.value for a in csr.subject if a.oid == NameOID.COMMON_NAME), None)
    try:
        sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    return cn, list(sans)


def csr_pem(csr_der: bytes) -> str:
    return x509.load_der_x509_csr(csr_der).public_bytes(serialization.Encoding.PEM).decode()


def parse_certs(data: bytes) -> list:
    """Certificates in a PEM bundle, a single DER certificate, or a PKCS#7 container."""
    data = data.strip()
    if b"-----BEGIN CERTIFICATE-----" in data:
        return x509.load_pem_x509_certificates(data)
    if b"-----BEGIN PKCS7-----" in data:
        return pkcs7.load_pem_pkcs7_certificates(data)
    try:
        return [x509.load_der_x509_certificate(data)]
    except ValueError:
        return pkcs7.load_der_pkcs7_certificates(data)


def order_chain(certs: list, leaf_public_key) -> list:
    """Leaf (the certificate for OUR key) first, then each issuer in turn. Unrelated certificates are dropped."""
    want = spki_sha256(leaf_public_key)
    leaf = next((c for c in certs if spki_sha256(c.public_key()) == want), None)
    if leaf is None:
        raise CaPermanentError("the CA returned no certificate for the key Key Vault generated")
    chain, seen = [leaf], {leaf.fingerprint(hashes.SHA256())}
    cur = leaf
    while cur.subject != cur.issuer:
        nxt = next((c for c in certs if c.subject == cur.issuer and c.fingerprint(hashes.SHA256()) not in seen), None)
        if nxt is None:
            break
        chain.append(nxt)
        seen.add(nxt.fingerprint(hashes.SHA256()))
        cur = nxt
    return chain


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


# ----------------------------------------------------------------------------- DigiCert CertCentral
class DigiCertCaClient:
    """DigiCert CertCentral Services API. Request shapes follow dev.digicert.com (checked Oct 2026); NOT yet run against a live account.

    * A renewal REISSUES the existing order (POST /order/certificate/{order_id}/reissue). A reissued certificate has a new
      certificate id but the same order id, and a reissue inside the order term is not charged again.
    * A NEW order costs money, so it is refused unless allow_new_order is set. The usual first step for an existing DigiCert
      customer is to point the function at the order they already own (tag  kvrenew-order-id = <order id>).
    * Domain control validation (DCV) is NOT automated here. When the order needs DNS validation the DigiCert token is kept in
      the order record and shown in the log; until DCV passes the order stays 'pending' and the function keeps waiting.
    """

    def __init__(
        self,
        api_key: Callable[[], str],
        *,
        product: str,
        base_url: str = "https://www.digicert.com/services/v2",
        organization_id: Optional[int] = None,
        container_id: Optional[int] = None,
        order_years: int = 1,
        cert_validity_days: Optional[int] = None,
        dcv_method: Optional[str] = None,
        payment_method: Optional[str] = None,
        server_platform_id: int = 2,  # the value used in DigiCert's own examples; we always download pem_all, so the platform does not matter
        reissue: bool = True,
        allow_new_order: bool = False,
        skip_approval: bool = False,
        session=None,
        timeout: int = 30,
        clock: Callable[[], dt.datetime] = _now,
    ) -> None:
        import requests

        self._key = api_key
        self.product = product
        self.base = base_url.rstrip("/")
        self.org = organization_id
        self.container = container_id
        self.order_years = order_years
        self.cert_validity_days = cert_validity_days
        self.dcv = dcv_method
        self.payment = payment_method
        self.platform = server_platform_id
        self.reissue = reissue
        self.allow_new_order = allow_new_order
        self.skip_approval = skip_approval
        self.http = session or requests.Session()
        self.timeout = timeout
        self._clock = clock

    # -- transport
    def _call(self, method: str, path: str, *, body: Optional[dict] = None, accept: str = "application/json"):
        import requests

        headers = {"X-DC-DEVKEY": self._key(), "Accept": accept}
        if body is not None:
            headers["Content-Type"] = "application/json"
        try:
            r = self.http.request(method, self.base + path, headers=headers, data=json.dumps(body) if body is not None else None, timeout=self.timeout)
        except requests.RequestException as e:
            raise CaTransientError(f"DigiCert {method} {path}: {type(e).__name__}") from e
        if r.status_code in (408, 429) or r.status_code >= 500:
            raise CaTransientError(f"DigiCert {method} {path}: HTTP {r.status_code}")
        if r.status_code >= 400:
            raise CaPermanentError(f"DigiCert {method} {path}: HTTP {r.status_code} {_errors(r)}")
        return r

    # -- CaClient
    def submit(self, csr_der: bytes, previous_order_id: Optional[str]) -> CaOrder:
        cn, sans = csr_names(csr_der)
        if not cn:
            raise CaPermanentError("the CSR has no common name")
        cert = {
            "common_name": cn,
            "dns_names": [n for n in sans if n.lower() != cn.lower()],
            "csr": csr_pem(csr_der),
            "signature_hash": "sha256",
            "server_platform": {"id": self.platform},
        }
        extra = {"spki": spki_sha256(x509.load_der_x509_csr(csr_der).public_key())}
        renewal_of = None
        if previous_order_id and self.reissue:
            info = self._order_info(previous_order_id)
            got = ((info.get("certificate") or {}).get("common_name") or "").lower()
            if got and got != cn.lower():
                raise CaPermanentError(f"DigiCert order {previous_order_id} is for {got}, not {cn}; refusing to reissue another name's order")
            if str(info.get("status", "")).lower() != "expired":
                body: dict = {"certificate": cert}
                if self.skip_approval:
                    body["skip_approval"] = True
                resp = self._call("POST", f"/order/certificate/{previous_order_id}/reissue", body=body)
                extra["kind"] = "reissue"
                try:
                    rj = resp.json()
                except ValueError:
                    rj = None
                if isinstance(rj, dict) and rj.get("dcv_random_value"):
                    extra["dcv"] = {"method": self.dcv or "", "token": str(rj["dcv_random_value"])}
                return CaOrder(order_id=str(previous_order_id), ordered_utc=_iso(self._clock()), extra=extra)
            renewal_of = previous_order_id  # the order term is over: a reissue is no longer possible, a (paid) renewal is
        if not self.allow_new_order:
            why = f"DigiCert order {previous_order_id} has expired" if renewal_of else "no DigiCert order is recorded for this certificate"
            raise CaPermanentError(
                f"{why}. A new order is a purchase, so it is not placed automatically. Order it in CertCentral and tag the certificate "
                "kvrenew-order-id=<order id> to have it reissued from then on, or set DIGICERT_ALLOW_NEW_ORDER=true to let the function buy."
            )
        if not self.product:
            raise CaPermanentError("DIGICERT_PRODUCT is not set; it names the CertCentral product (name_id) a new order would buy")
        # order_validity is how long the ORDER (the subscription that allows free reissues) lasts. How long each CERTIFICATE lives is
        # decided by DigiCert: since 24 Feb 2026 a public TLS certificate is capped at 199 days, and it will keep shrinking
        # (99 days from 2027-03-15, 46 from 2029-03-15). cert_validity is only honoured on multi-year-plan accounts and its exact
        # placement in the request is taken from DigiCert's documentation, not from a live call.
        body = {"certificate": cert, "order_validity": {"years": self.order_years}}
        if self.cert_validity_days:
            body["cert_validity"] = {"days": self.cert_validity_days}
        if self.org:
            body["organization"] = {"id": self.org}
        if self.container:
            body["container"] = {"id": self.container}
        if self.payment:
            body["payment_method"] = self.payment
        if self.dcv:
            body["dcv_method"] = self.dcv
        if self.skip_approval:
            body["skip_approval"] = True
        if renewal_of:
            body["renewal_of_order_id"] = int(renewal_of)
        j = self._call("POST", f"/order/certificate/{self.product}", body=body).json()
        extra["kind"] = "renewal" if renewal_of else "new"
        if j.get("dcv_random_value"):
            extra["dcv"] = {"method": self.dcv or "", "token": str(j["dcv_random_value"])}
        return CaOrder(order_id=str(j["id"]), ordered_utc=_iso(self._clock()), extra=extra)

    def _order_info(self, order_id: str) -> dict:
        return self._call("GET", f"/order/certificate/{order_id}").json()

    def status(self, order: CaOrder) -> CaStatus:
        j = self._order_info(order.order_id)
        top = str(j.get("status", "")).lower()
        if top in ("rejected", "revoked", "canceled", "cancelled", "expired"):
            return CaStatus("failed", f"order status {top}")
        c = j.get("certificate") or {}
        got = _csr_spki(c.get("csr"))
        want = order.extra.get("spki")
        if top == "issued" and c.get("id"):
            if got is not None:
                matches = got == want  # the order echoes the CSR of its current certificate: it must be ours
            else:
                # The response did not echo the CSR. A reissue that is still pending means the order still shows the previous
                # certificate; otherwise fetch_chain() proves the key match before anything is merged.
                matches = not (order.extra.get("kind") == "reissue" and j.get("pending_reissue"))
            if matches:
                return CaStatus("issued", "issued", certificate_id=str(c["id"]))
        detail = f"order status {top or 'unknown'}"
        if top == "needs_approval":
            detail += "; a CertCentral administrator must approve the request (or set DIGICERT_SKIP_APPROVAL=true with an administrator key)"
        elif top == "waiting_pickup":
            detail += "; CertCentral lists the order as waiting for pickup, it is not downloadable yet"
        elif top in ("pending", "reissue_pending", "processing") and (order.extra.get("dcv") or {}).get("token"):
            d = order.extra["dcv"]
            detail += f"; domain validation may be pending ({d.get('method') or 'dcv'} token {d['token']})"
        return CaStatus("pending", detail)

    def fetch_chain(self, order: CaOrder, csr_der: bytes) -> list:
        st = self.status(order)
        if st.state != "issued" or not st.certificate_id:
            raise CaTransientError("the order is not issued yet")
        r = self._call("GET", f"/certificate/{st.certificate_id}/download/format/pem_all", accept="*/*")
        try:
            chain = order_chain(parse_certs(r.content), x509.load_der_x509_csr(csr_der).public_key())
        except CaPermanentError as e:
            # While a reissue is in flight the order can still point at the previous certificate. Wait, do not fail.
            raise CaTransientError(f"the certificate DigiCert returned is not for the new key yet ({e})") from e
        return [c.public_bytes(serialization.Encoding.DER) for c in chain]


def _csr_spki(pem: Optional[str]) -> Optional[str]:
    if not pem:
        return None
    try:
        return spki_sha256(x509.load_pem_x509_csr(pem.encode()).public_key())
    except ValueError:
        return None


def _errors(r) -> str:
    try:
        errs = r.json().get("errors") or []
        return "; ".join(f"{e.get('code')}: {e.get('message')}" for e in errs)[:300]
    except ValueError:
        return (r.text or "")[:200]


# ----------------------------------------------------------------------------- private test CA (POC only)
class LocalTestCaClient:
    """Signs the CSR with a private test CA. The CA bundle is a Key Vault secret:  {"ca_cert_pem": ..., "ca_key_pem": ...}."""

    def __init__(self, bundle: Callable[[], dict], *, days: int = 90, delay_seconds: int = 0, clock: Callable[[], dt.datetime] = _now) -> None:
        self._bundle = bundle
        self.days = days
        self.delay = delay_seconds
        self._clock = clock

    def submit(self, csr_der: bytes, previous_order_id: Optional[str]) -> CaOrder:
        return CaOrder(order_id=f"testca-{uuid.uuid4().hex[:12]}", ordered_utc=_iso(self._clock()))

    def status(self, order: CaOrder) -> CaStatus:
        ordered = dt.datetime.strptime(order.ordered_utc, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
        if (self._clock() - ordered).total_seconds() < self.delay:
            return CaStatus("pending", "test CA is simulating validation delay")
        return CaStatus("issued", "issued", certificate_id=order.order_id)

    def fetch_chain(self, order: CaOrder, csr_der: bytes) -> list:
        b = self._bundle()
        ca_cert = x509.load_pem_x509_certificate(b["ca_cert_pem"].encode())
        ca_key = serialization.load_pem_private_key(b["ca_key_pem"].encode(), password=None)
        csr = x509.load_der_x509_csr(csr_der)
        if not csr.is_signature_valid:
            raise CaPermanentError("CSR signature is invalid")
        now = self._clock()
        builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=self.days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_encipherment=True, content_commitment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
        )
        try:
            builder = builder.add_extension(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value, critical=False)
        except x509.ExtensionNotFound:
            pass
        leaf = builder.sign(ca_key, hashes.SHA256())
        return [leaf.public_bytes(serialization.Encoding.DER), ca_cert.public_bytes(serialization.Encoding.DER)]


def make_ca(provider: str, env: dict, secret_value: Callable[[str], str]):
    """Build the CA client selected by CA_PROVIDER. `secret_value(name)` reads a secret from the source vault."""
    p = (provider or "").strip().lower()
    if p == "digicert":
        key_name = env.get("CA_SECRET_NAME", "ca-digicert-api-key")

        def opt_int(k):
            v = env.get(k)
            return int(v) if v else None

        def flag(k, default="false"):
            return env.get(k, default).strip().lower() in ("1", "true", "yes", "on")

        return DigiCertCaClient(
            lambda: secret_value(key_name).strip(),
            product=env.get("DIGICERT_PRODUCT", ""),
            base_url=env.get("DIGICERT_API_BASE", "https://www.digicert.com/services/v2"),
            organization_id=opt_int("DIGICERT_ORGANIZATION_ID"),
            container_id=opt_int("DIGICERT_CONTAINER_ID"),
            order_years=opt_int("DIGICERT_ORDER_YEARS") or 1,
            cert_validity_days=opt_int("DIGICERT_CERT_VALIDITY_DAYS"),
            dcv_method=env.get("DIGICERT_DCV_METHOD") or None,
            payment_method=env.get("DIGICERT_PAYMENT_METHOD") or None,
            server_platform_id=opt_int("DIGICERT_SERVER_PLATFORM_ID") if env.get("DIGICERT_SERVER_PLATFORM_ID") else 2,
            reissue=flag("DIGICERT_REISSUE", "true"),
            allow_new_order=flag("DIGICERT_ALLOW_NEW_ORDER"),
            skip_approval=flag("DIGICERT_SKIP_APPROVAL"),
        )
    if p == "testca":
        name = env.get("TESTCA_SECRET_NAME", "ca-testca-bundle")
        return LocalTestCaClient(
            lambda: json.loads(secret_value(name)),
            days=int(env.get("TESTCA_DAYS", "90")),
            delay_seconds=int(env.get("TESTCA_DELAY_SECONDS", "0")),
        )
    raise ValueError(f"CA_PROVIDER must be 'digicert' or 'testca', got {provider!r}")
