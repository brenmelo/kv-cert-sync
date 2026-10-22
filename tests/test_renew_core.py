"""Offline tests for the renewal state machine, the DigiCert client and the test CA. No Azure access needed.

    python -m unittest discover -s function-renew/tests -v
"""
import datetime as dt
import json
import pathlib
import sys
import types
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src" / "renew"))

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from kvrenew import core  # noqa: E402
from kvrenew.ca import (  # noqa: E402
    CaOrder, CaPermanentError, CaStatus, CaTransientError, DigiCertCaClient, LocalTestCaClient, order_chain, parse_certs,
)
from kvrenew.state import MemoryStore  # noqa: E402

T0 = dt.datetime(2026, 11, 1, 12, 0, 0, tzinfo=dt.timezone.utc)


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += dt.timedelta(seconds=s)


def make_ca_bundle(cn="Test Root CA"):
    key = rsa.generate_private_key(65537, 2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(T0 - dt.timedelta(days=1)).not_valid_after(T0 + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256())
    )
    return {
        "ca_cert_pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "ca_key_pem": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
    }


def policy(issuer="Unknown", subject="CN=*.example.test", sans=("*.example.test", "example.test")):
    return types.SimpleNamespace(
        issuer_name=issuer, exportable=True, key_type="RSA", key_size=2048, key_curve_name=None, reuse_key=False,
        content_type="application/x-pkcs12", subject=subject, san_dns_names=list(sans), san_emails=None,
        san_user_principal_names=None, key_usage=None, enhanced_key_usage=None, validity_in_months=3, lifetime_actions=None,
    )


class FakeCerts:
    """Just enough of CertificateClient: current versions, pending operations, merge."""

    def __init__(self, clock):
        self.clock = clock
        self.cur = {}  # name -> KeyVaultCertificate-like
        self.ops = {}  # name -> namespace(status, csr, key, tags, policy)
        self.created = []  # (name, policy, tags) for every begin_create_certificate
        self.merges = []

    def add_issued(self, name, *, lifetime_days, left_days, tags, pol=None, age_hours=1000):
        now = self.clock.now()
        exp = now + dt.timedelta(days=left_days)
        self.cur[name] = self._cert(name, exp - dt.timedelta(days=lifetime_days), exp, now - dt.timedelta(hours=age_hours), tags, pol or policy())

    @staticmethod
    def _cert(name, nb, exp, created, tags, pol, version="v1"):
        props = types.SimpleNamespace(name=name, version=version, tags=dict(tags), not_before=nb, expires_on=exp, created_on=created)
        return types.SimpleNamespace(properties=props, policy=pol)

    def get_certificate(self, name):
        if name not in self.cur:
            raise ResourceNotFoundError("not found")
        return self.cur[name]

    def get_certificate_operation(self, name):
        if name not in self.ops:
            raise ResourceNotFoundError("no operation")
        o = self.ops[name]
        return types.SimpleNamespace(status=o.status, csr=o.csr)

    def list_properties_of_certificates(self, include_pending=False):
        out = [c.properties for c in self.cur.values()]
        if include_pending:
            out += [types.SimpleNamespace(name=n, tags=o.tags) for n, o in self.ops.items() if n not in self.cur and o.status == "inProgress"]
        return out

    def begin_create_certificate(self, name, pol, enabled=None, tags=None):
        if name in self.ops and self.ops[name].status == "inProgress":
            raise HttpResponseError("Conflict: a pending operation exists")
        self.created.append((name, pol, dict(tags or {})))
        key = rsa.generate_private_key(65537, 2048)
        cn = pol.subject.split("=", 1)[1]
        b = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        if pol.san_dns_names:
            b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in pol.san_dns_names]), critical=False)
        csr = b.sign(key, hashes.SHA256())
        self.ops[name] = types.SimpleNamespace(
            status="inProgress", csr=csr.public_bytes(serialization.Encoding.DER), key=key, tags=dict(tags or {}), policy=pol
        )

    def merge_certificate(self, name, x509_certificates, tags=None):
        o = self.ops[name]
        leaf = x509.load_der_x509_certificate(x509_certificates[0])
        if leaf.public_key().public_numbers() != o.key.public_key().public_numbers():
            raise HttpResponseError("the certificate does not match the pending key")
        self.merges.append([x509.load_der_x509_certificate(c).subject.rfc4514_string() for c in x509_certificates])
        version = f"v{len(self.merges) + 1}"
        self.cur[name] = self._cert(name, leaf.not_valid_before_utc, leaf.not_valid_after_utc, self.clock.now(), tags or o.tags, o.policy, version)
        o.status = "completed"
        return self.cur[name]


class CountingCa:
    """Wraps a CA client and counts submissions."""

    def __init__(self, inner):
        self.inner, self.submits, self.fetches = inner, [], 0

    def submit(self, csr_der, previous_order_id):
        self.submits.append(previous_order_id)
        return self.inner.submit(csr_der, previous_order_id)

    def status(self, order):
        return self.inner.status(order)

    def fetch_chain(self, order, csr_der):
        self.fetches += 1
        return self.inner.fetch_chain(order, csr_der)


BUNDLE = make_ca_bundle()
TAGS = {"kvsync": "all", "kvrenew": "on", "owner": "platform"}


def build(clock=None, *, ca=None, delay=0, settings=None):
    clock = clock or Clock()
    certs = FakeCerts(clock)
    ca = ca or CountingCa(LocalTestCaClient(lambda: BUNDLE, days=90, delay_seconds=delay, clock=clock.now))
    store = MemoryStore()
    ctx = core.Context(certs=certs, ca=ca, store=store, settings=settings or core.Settings(poll_seconds=30, poll_interval=10), now=clock.now, sleep=clock.sleep)
    return ctx, certs, ca, store, clock


def _sign_leaf(csr, dns_names, days=90):
    ca_cert = x509.load_pem_x509_certificate(BUNDLE["ca_cert_pem"].encode())
    ca_key = serialization.load_pem_private_key(BUNDLE["ca_key_pem"].encode(), password=None)
    leaf = (
        x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca_cert.subject).public_key(csr.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(T0 - dt.timedelta(minutes=5)).not_valid_after(T0 + dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in dns_names]), False).sign(ca_key, hashes.SHA256())
    )
    return [leaf.public_bytes(serialization.Encoding.DER), ca_cert.public_bytes(serialization.Encoding.DER)]


class RenewalStateMachine(unittest.TestCase):
    def test_not_opted_in_is_ignored(self):
        ctx, certs, *_ = build()
        certs.add_issued("c1", lifetime_days=90, left_days=1, tags={"kvsync": "all"})
        self.assertEqual(core.renew_certificate("c1", ctx, trigger="t")["result"], "not-opted-in")
        self.assertEqual(certs.created, [])

    def test_not_due(self):
        ctx, certs, *_ = build()
        certs.add_issued("c1", lifetime_days=90, left_days=60, tags=TAGS)
        r = core.renew_certificate("c1", ctx, trigger="t")
        self.assertEqual(r["result"], "not-due")
        self.assertEqual(certs.created, [])

    def test_due_renews_end_to_end_with_new_key_and_carried_tags(self):
        ctx, certs, ca, store, clock = build()
        certs.add_issued("c1", lifetime_days=90, left_days=20, tags=TAGS)
        r = core.renew_certificate("c1", ctx, trigger="timer")
        self.assertEqual(r["result"], "merged", r)
        name, pol, tags = certs.created[0]
        self.assertFalse(pol.reuse_key, "a renewal must use a NEW key")
        self.assertEqual(pol.issuer_name, "Unknown")
        self.assertEqual(tags, TAGS, "kvsync/kvrenew tags must carry over so replication continues")
        self.assertEqual(certs.cur["c1"].properties.version, "v2")
        self.assertEqual(len(certs.merges[0]), 2, "leaf + CA")
        data, _ = store.get("c1")
        self.assertEqual(data["status"], "merged")
        self.assertIsNone(data["csr_sha256"])
        self.assertIsNone(data["lease_until"])
        # the fresh certificate is 90 days: nothing more to do
        self.assertEqual(core.renew_certificate("c1", ctx, trigger="timer")["result"], "not-due")

    def test_restart_resumes_without_ordering_twice(self):
        ctx, certs, ca, store, clock = build(delay=3600)
        certs.add_issued("c1", lifetime_days=90, left_days=20, tags=TAGS)
        self.assertEqual(core.renew_certificate("c1", ctx, trigger="timer")["result"], "waiting")
        clock.t += dt.timedelta(minutes=5)
        self.assertEqual(core.renew_certificate("c1", ctx, trigger="timer")["result"], "waiting")
        self.assertEqual(len(ca.submits), 1, "the order is recorded, so a new run must not order again")
        self.assertEqual(len(certs.created), 1)
        clock.t += dt.timedelta(hours=2)
        self.assertEqual(core.renew_certificate("c1", ctx, trigger="timer")["result"], "merged")
        self.assertEqual(len(ca.submits), 1)

    def test_second_request_with_prior_order_asks_for_reissue(self):
        ctx, certs, ca, store, clock = build()
        certs.add_issued("c1", lifetime_days=90, left_days=20, tags=TAGS)
        core.renew_certificate("c1", ctx, trigger="timer")
        first_order = store.get("c1")[0]["order_id"]
        certs.cur["c1"].properties.created_on = clock.t - dt.timedelta(days=80)
        certs.cur["c1"].properties.not_before = clock.t - dt.timedelta(days=85)
        certs.cur["c1"].properties.expires_on = clock.t + dt.timedelta(days=5)
        core.renew_certificate("c1", ctx, trigger="timer")
        self.assertEqual(ca.submits[0], None)
        self.assertEqual(ca.submits[1], first_order, "second renewal passes the previous order id (reissue)")

    def test_lease_blocks_concurrent_run(self):
        ctx, certs, ca, store, clock = build()
        certs.add_issued("c1", lifetime_days=90, left_days=20, tags=TAGS)
        store.put("c1", {"lease_until": core._iso(clock.t + dt.timedelta(minutes=5))}, None)
        self.assertEqual(core.renew_certificate("c1", ctx, trigger="timer")["result"], "busy")
        self.assertEqual(certs.created, [])

    def test_expired_lease_is_taken_over(self):
        ctx, certs, ca, store, clock = build()
        certs.add_issued("c1", lifetime_days=90, left_days=20, tags=TAGS)
        store.put("c1", {"lease_until": core._iso(clock.t - dt.timedelta(minutes=1))}, None)
        self.assertEqual(core.renew_certificate("c1", ctx, trigger="timer")["result"], "merged")

    def test_rate_limit(self):
        ctx, certs, ca, store, clock = build()
        certs.add_issued("c1", lifetime_days=90, left_days=20, tags=TAGS)
        store.put("c1", {"history": [core._iso(clock.t - dt.timedelta(hours=h)) for h in (1, 2, 3)]}, None)
        self.assertEqual(core.renew_certificate("c1", ctx, trigger="timer")["result"], "blocked-rate-limit")
        self.assertEqual(certs.created, [])

    def test_certificate_that_is_too_new_is_not_renewed_again(self):
        ctx, certs, ca, store, clock = build()
        certs.add_issued("c1", lifetime_days=90, left_days=20, tags=TAGS, age_hours=2)
        self.assertEqual(core.renew_certificate("c1", ctx, trigger="timer")["result"], "skipped-too-new")

    def test_short_lived_certificate_uses_a_third_of_its_life(self):
        ctx, certs, *_ = build()
        certs.add_issued("c1", lifetime_days=47, left_days=20, tags=TAGS)
        self.assertEqual(core.renew_certificate("c1", ctx, trigger="timer")["result"], "not-due")  # window is 15.7 days
        ctx2, certs2, *_ = build()
        certs2.add_issued("c1", lifetime_days=47, left_days=15, tags=TAGS)
        self.assertEqual(core.renew_certificate("c1", ctx2, trigger="timer")["result"], "merged")

    def test_per_certificate_window_override(self):
        ctx, certs, *_ = build()
        certs.add_issued("c1", lifetime_days=90, left_days=20, tags={**TAGS, "kvrenew-days": "10"})
        self.assertEqual(core.renew_certificate("c1", ctx, trigger="timer")["result"], "not-due")

    def test_force_tag_rotates_a_certificate_that_is_neither_due_nor_old_and_is_never_copied_forward(self):
        ctx, certs, ca, store, clock = build()
        certs.add_issued("c1", lifetime_days=90, left_days=85, tags={**TAGS, "kvrenew-now": "1"}, age_hours=2)
        r = core.renew_certificate("c1", ctx, trigger="timer")
        self.assertEqual(r["result"], "merged", r)
        self.assertEqual(len(certs.created), 1)
        self.assertNotIn("kvrenew-now", certs.created[0][2], "the pending request must not carry the one-shot tag")
        self.assertNotIn("kvrenew-now", certs.cur["c1"].properties.tags, "the merged version must not carry the one-shot tag")
        self.assertEqual(certs.cur["c1"].properties.version, "v2")
        self.assertEqual(core.renew_certificate("c1", ctx, trigger="timer")["result"], "not-due", "no rotation loop")
        self.assertEqual(len(ca.submits), 1)

    def test_force_tag_survives_a_slow_ca_without_leaking_into_the_new_version(self):
        ctx, certs, ca, store, clock = build(delay=3600)
        certs.add_issued("c1", lifetime_days=90, left_days=85, tags={**TAGS, "kvrenew-now": "1"})
        self.assertEqual(core.renew_certificate("c1", ctx, trigger="timer")["result"], "waiting")
        clock.t += dt.timedelta(minutes=5)
        self.assertEqual(core.renew_certificate("c1", ctx, trigger="timer")["result"], "waiting")  # old version still has the tag
        self.assertEqual(len(ca.submits), 1, "still one order")
        clock.t += dt.timedelta(hours=2)
        self.assertEqual(core.renew_certificate("c1", ctx, trigger="timer")["result"], "merged")
        self.assertNotIn("kvrenew-now", certs.cur["c1"].properties.tags)
        self.assertEqual(core.renew_certificate("c1", ctx, trigger="timer")["result"], "not-due")

    def test_force_tag_does_not_bypass_the_rate_limit(self):
        ctx, certs, ca, store, clock = build()
        certs.add_issued("c1", lifetime_days=90, left_days=85, tags={**TAGS, "kvrenew-now": "1"})
        store.put("c1", {"history": [core._iso(clock.t - dt.timedelta(hours=h)) for h in (1, 2, 3)]}, None)
        self.assertEqual(core.renew_certificate("c1", ctx, trigger="timer")["result"], "blocked-rate-limit")
        self.assertEqual(certs.created, [])

    def test_force_tag_is_ignored_on_a_replica_and_on_a_certificate_that_is_not_opted_in(self):
        ctx, certs, *_ = build()
        certs.add_issued("replica", lifetime_days=90, left_days=85, tags={**TAGS, "kvsync-origin": "kv-src", "kvrenew-now": "1"})
        certs.add_issued("other", lifetime_days=90, left_days=85, tags={"kvsync": "all", "kvrenew-now": "1"})
        self.assertEqual(core.renew_certificate("replica", ctx, trigger="timer")["result"], "skipped-replica")
        self.assertEqual(core.renew_certificate("other", ctx, trigger="timer")["result"], "not-opted-in")
        self.assertEqual(certs.created, [])

    def test_order_id_tag_seeds_the_first_reissue(self):
        ctx, certs, ca, store, clock = build()
        certs.add_issued("c1", lifetime_days=90, left_days=20, tags={**TAGS, "kvrenew-order-id": "777"})
        core.renew_certificate("c1", ctx, trigger="timer")
        self.assertEqual(ca.submits, ["777"], "an order the customer already owns is reissued, not bought again")

    def test_a_year_of_daily_reconciles_never_lets_a_certificate_lapse(self):
        """The CA/B Forum schedule: 199 d now (DigiCert, since 2026-02-24), 99 d from 2027-03-15, 46 d from 2029-03-15."""
        for days, lo, hi in ((199, 2, 3), (99, 5, 6), (46, 11, 12)):
            with self.subTest(validity_days=days):
                clock = Clock()
                ca = CountingCa(LocalTestCaClient(lambda: BUNDLE, days=days, clock=clock.now))
                ctx, certs, ca, store, _ = build(clock, ca=ca)
                certs.add_issued("c1", lifetime_days=days, left_days=days, tags=TAGS)
                lowest = float(days)
                for _ in range(365):
                    clock.t += dt.timedelta(days=1)
                    core.reconcile_renewals(ctx)
                    lowest = min(lowest, (certs.cur["c1"].properties.expires_on - clock.now()).total_seconds() / 86400)
                renewals = len(certs.merges)
                self.assertTrue(lo <= renewals <= hi, f"{days}-day certificates: {renewals} renewals in a year")
                self.assertGreater(lowest, 10, f"{days}-day certificates must never get closer than ~a third of their life to expiry")
                self.assertEqual(len(ca.submits), renewals, "exactly one CA request per renewal")
                print(f"\n  {days:>3}-day certificates: {renewals} renewals/year, tightest margin {lowest:.1f} days left")

    def test_replica_is_never_renewed(self):
        ctx, certs, *_ = build()
        certs.add_issued("c1", lifetime_days=90, left_days=1, tags={**TAGS, "kvsync-origin": "kv-source"})
        self.assertEqual(core.renew_certificate("c1", ctx, trigger="timer")["result"], "skipped-replica")

    def test_key_vault_managed_issuer_is_left_alone(self):
        ctx, certs, *_ = build()
        certs.add_issued("c1", lifetime_days=90, left_days=1, tags=TAGS, pol=policy(issuer="DigiCert"))
        self.assertEqual(core.renew_certificate("c1", ctx, trigger="timer")["result"], "skipped-managed-issuer")
        self.assertEqual(certs.created, [])

    def test_first_issuance_of_an_operator_created_pending_request(self):
        ctx, certs, ca, store, clock = build()
        certs.begin_create_certificate("new1", policy(), tags=TAGS)  # created by a person; there is no current version
        self.assertNotIn("new1", certs.cur)
        self.assertEqual(core.renew_certificate("new1", ctx, trigger="timer")["result"], "merged")
        self.assertEqual(len(certs.created), 1, "must reuse the pending request, not create another")

    def test_reconcile_visits_opted_in_certificates_only(self):
        ctx, certs, *_ = build()
        certs.add_issued("a", lifetime_days=90, left_days=20, tags=TAGS)
        certs.add_issued("b", lifetime_days=90, left_days=20, tags={"kvsync": "all"})
        certs.begin_create_certificate("p", policy(), tags=TAGS)
        s = core.reconcile_renewals(ctx)
        self.assertEqual(s, {"merged": 2})

    def test_sweep_continues_after_any_exception_and_reports_it_as_one_line(self):
        # not only a CA outage: a Key Vault 403 or a storage error must not stop the sweep for the other certificates
        ctx, certs, ca, store, clock = build()
        certs.add_issued("a", lifetime_days=90, left_days=20, tags=TAGS)
        certs.add_issued("b", lifetime_days=90, left_days=20, tags=TAGS)
        real = certs.get_certificate

        def get_certificate(name):
            if name == "a":
                raise HttpResponseError("Caller is not authorized\nCode: Forbidden\nInner error: ForbiddenByRbac")
            return real(name)

        certs.get_certificate = get_certificate
        with self.assertLogs("kvrenew", level="INFO") as captured:
            with self.assertRaises(CaTransientError):
                core.reconcile_renewals(ctx)
        self.assertEqual(certs.cur["b"].properties.version, "v2", "the other certificate was still renewed")
        data_a = store.get("a")[0]
        self.assertTrue(data_a is None or data_a["lease_until"] is None, "the lease of the failing certificate is released")
        failed = [m for m in captured.output if "result=failed-transient" in m]
        self.assertEqual(len(failed), 1, captured.output)
        self.assertIn("cert=a", failed[0])
        self.assertIn("error=HttpResponseError", failed[0])
        self.assertIn("ForbiddenByRbac", failed[0])
        self.assertNotIn("\n", failed[0], "one line, so a log query shows it whole")
        done = [m for m in captured.output if "result=reconcile-complete" in m]
        self.assertEqual(len(done), 1, "the sweep still reports completion (the heartbeat rule keys on it)")
        self.assertIn("failures=1", done[0])

    def test_one_line_collapses_whitespace_and_is_capped(self):
        self.assertEqual(core.one_line(HttpResponseError("a\n  b\r\n\tc")), "a b c")
        self.assertLessEqual(len(core.one_line(RuntimeError("x" * 5000))), 600)
        self.assertEqual(core.one_line(RuntimeError("")), "RuntimeError")

    def test_transient_ca_error_propagates_and_releases_the_lease(self):
        class Flaky:
            def submit(self, csr, prev):
                raise CaTransientError("HTTP 503")

            status = fetch_chain = submit

        ctx, certs, ca, store, clock = build(ca=Flaky())
        certs.add_issued("c1", lifetime_days=90, left_days=20, tags=TAGS)
        with self.assertRaises(CaTransientError):
            core.renew_certificate("c1", ctx, trigger="timer")
        self.assertIsNone(store.get("c1")[0]["lease_until"])

    def test_rejected_order_is_permanent_and_not_retried(self):
        class Rejects(CountingCa):
            def status(self, order):
                return CaStatus("failed", "order status rejected")

        inner = Rejects(LocalTestCaClient(lambda: BUNDLE))
        ctx, certs, ca, store, clock = build(ca=inner)
        certs.add_issued("c1", lifetime_days=90, left_days=20, tags=TAGS)
        self.assertEqual(core.renew_certificate("c1", ctx, trigger="timer")["result"], "failed-permanent")
        self.assertEqual(core.renew_certificate("c1", ctx, trigger="timer")["result"], "failed-permanent")
        self.assertEqual(len(inner.submits), 1, "a failed order for the same CSR is never re-ordered")

    def test_certificate_for_a_different_key_is_refused(self):
        other = LocalTestCaClient(lambda: BUNDLE)

        class WrongKey(CountingCa):
            def fetch_chain(self, order, csr_der):
                k = rsa.generate_private_key(65537, 2048)
                c = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "*.example.test")])).sign(k, hashes.SHA256())
                return other.fetch_chain(order, c.public_bytes(serialization.Encoding.DER))

        ctx, certs, ca, store, clock = build(ca=WrongKey(other))
        certs.add_issued("c1", lifetime_days=90, left_days=20, tags=TAGS)
        r = core.renew_certificate("c1", ctx, trigger="timer")
        self.assertEqual(r["result"], "failed-permanent")
        self.assertEqual(certs.merges, [])

    def test_certificate_missing_a_requested_name_is_refused(self):
        class OnlyOneName(CountingCa):
            def fetch_chain(self, order, csr_der):
                return _sign_leaf(x509.load_der_x509_csr(csr_der), ["*.example.test"])

        ctx, certs, ca, store, clock = build(ca=OnlyOneName(LocalTestCaClient(lambda: BUNDLE)))
        certs.add_issued("c1", lifetime_days=90, left_days=20, tags=TAGS)
        r = core.renew_certificate("c1", ctx, trigger="timer")
        self.assertEqual(r["result"], "failed-permanent")
        self.assertEqual(certs.merges, [])


class ChainOrdering(unittest.TestCase):
    def test_leaf_first_unrelated_dropped_shuffled_input(self):
        root = make_ca_bundle("Root")
        root_cert = x509.load_pem_x509_certificate(root["ca_cert_pem"].encode())
        root_key = serialization.load_pem_private_key(root["ca_key_pem"].encode(), password=None)
        inter_key = rsa.generate_private_key(65537, 2048)
        inter = (
            x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate")])).issuer_name(root_cert.subject)
            .public_key(inter_key.public_key()).serial_number(1).not_valid_before(T0).not_valid_after(T0 + dt.timedelta(days=100))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True).sign(root_key, hashes.SHA256())
        )
        leaf_key = rsa.generate_private_key(65537, 2048)
        leaf = (
            x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")])).issuer_name(inter.subject)
            .public_key(leaf_key.public_key()).serial_number(2).not_valid_before(T0).not_valid_after(T0 + dt.timedelta(days=50)).sign(inter_key, hashes.SHA256())
        )
        stray = x509.load_pem_x509_certificate(make_ca_bundle("Stray")["ca_cert_pem"].encode())
        pem = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in (root_cert, stray, leaf, inter))
        chain = order_chain(parse_certs(pem), leaf_key.public_key())
        self.assertEqual([c.subject.rfc4514_string() for c in chain], ["CN=leaf", "CN=Intermediate", "CN=Root"])

    def test_no_certificate_for_our_key(self):
        pem = make_ca_bundle()["ca_cert_pem"].encode()
        with self.assertRaises(CaPermanentError):
            order_chain(parse_certs(pem), rsa.generate_private_key(65537, 2048).public_key())


class FakeResponse:
    def __init__(self, status=200, body=None, text=None):
        self.status_code = status
        self._body = body
        self.text = text if text is not None else (json.dumps(body) if body is not None else "")
        self.content = self.text.encode()

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class FakeSession:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def request(self, method, url, headers=None, data=None, timeout=None):
        path = url.split("/services/v2", 1)[1]
        self.calls.append((method, path, headers, json.loads(data) if data else None))
        r = self.routes[(method, path)]
        r = r.pop(0) if isinstance(r, list) else r
        if isinstance(r, Exception):
            raise r
        return r


def csr_for(key, cn="*.example.test", sans=("*.example.test", "example.test")):
    b = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
    b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]), False)
    return b.sign(key, hashes.SHA256())


class DigiCertClient(unittest.TestCase):
    def setUp(self):
        self.key = rsa.generate_private_key(65537, 2048)
        self.csr = csr_for(self.key)
        self.csr_der = self.csr.public_bytes(serialization.Encoding.DER)
        self.csr_pem = self.csr.public_bytes(serialization.Encoding.PEM).decode()

    def client(self, routes, **kw):
        s = FakeSession(routes)
        c = DigiCertCaClient(lambda: "secret-key", product="ssl_wildcard", session=s, clock=lambda: T0, **kw)
        return c, s

    def test_new_order_request_shape(self):
        c, s = self.client(
            {("POST", "/order/certificate/ssl_wildcard"): FakeResponse(201, {"id": 4242, "certificate_id": 9, "dcv_random_value": "tok123"})},
            organization_id=77, container_id=5, dcv_method="dns-txt-token", payment_method="balance", allow_new_order=True,
        )
        o = c.submit(self.csr_der, None)
        self.assertEqual(o.order_id, "4242")
        method, path, headers, body = s.calls[0]
        self.assertEqual(headers["X-DC-DEVKEY"], "secret-key")
        self.assertEqual(body["certificate"]["common_name"], "*.example.test")
        self.assertEqual(body["certificate"]["dns_names"], ["example.test"], "the CN is not repeated as a SAN")
        self.assertEqual(body["certificate"]["csr"], self.csr_pem)
        self.assertEqual(body["certificate"]["server_platform"], {"id": 2})
        self.assertEqual(body["organization"], {"id": 77})
        self.assertEqual(body["container"], {"id": 5})
        self.assertEqual(body["payment_method"], "balance")
        self.assertEqual(body["dcv_method"], "dns-txt-token")
        self.assertEqual(body["order_validity"], {"years": 1})
        self.assertNotIn("skip_approval", body, "approval is only skipped when asked for")
        self.assertEqual(o.extra["kind"], "new")
        self.assertEqual(o.extra["dcv"], {"method": "dns-txt-token", "token": "tok123"})

    def test_a_new_paid_order_is_refused_unless_explicitly_allowed(self):
        c, s = self.client({})
        with self.assertRaises(CaPermanentError) as cm:
            c.submit(self.csr_der, None)
        self.assertIn("kvrenew-order-id", str(cm.exception))
        self.assertIn("DIGICERT_ALLOW_NEW_ORDER", str(cm.exception))
        self.assertEqual(s.calls, [], "nothing may be sent to DigiCert")

    def test_renewal_reissues_the_existing_order(self):
        c, s = self.client({
            ("GET", "/order/certificate/4242"): FakeResponse(200, {"status": "issued", "certificate": {"common_name": "*.example.test"}}),
            ("POST", "/order/certificate/4242/reissue"): FakeResponse(201, {"id": 4242, "requests": [{"id": 2}]}),
        })
        o = c.submit(self.csr_der, "4242")
        self.assertEqual(o.order_id, "4242", "a reissue keeps the order id")
        self.assertEqual(s.calls[-1][1], "/order/certificate/4242/reissue")
        self.assertEqual(o.extra["kind"], "reissue")
        self.assertNotIn("skip_approval", s.calls[-1][3])
        self.assertNotIn("order_validity", s.calls[-1][3], "a reissue never buys anything")

    def test_reissue_surfaces_a_validation_token_when_digicert_returns_one(self):
        c, _ = self.client({
            ("GET", "/order/certificate/4242"): FakeResponse(200, {"status": "issued", "certificate": {"common_name": "*.example.test"}}),
            ("POST", "/order/certificate/4242/reissue"): FakeResponse(201, {"id": 4242, "certificate_id": 3, "dcv_random_value": "tok999"}),
        }, dcv_method="dns-txt-token")
        o = c.submit(self.csr_der, "4242")
        self.assertEqual(o.extra["dcv"], {"method": "dns-txt-token", "token": "tok999"})

    def test_a_reissue_response_without_json_is_tolerated(self):
        c, _ = self.client({
            ("GET", "/order/certificate/4242"): FakeResponse(200, {"status": "issued", "certificate": {"common_name": "*.example.test"}}),
            ("POST", "/order/certificate/4242/reissue"): FakeResponse(204),
        })
        self.assertEqual(c.submit(self.csr_der, "4242").order_id, "4242")

    def test_a_new_order_needs_a_product_name(self):
        s = FakeSession({})
        c = DigiCertCaClient(lambda: "k", product="", session=s, clock=lambda: T0, allow_new_order=True)
        with self.assertRaises(CaPermanentError) as cm:
            c.submit(self.csr_der, None)
        self.assertIn("DIGICERT_PRODUCT", str(cm.exception))
        self.assertEqual(s.calls, [])

    def test_skip_approval_is_sent_only_when_configured(self):
        c, s = self.client({
            ("GET", "/order/certificate/4242"): FakeResponse(200, {"status": "issued", "certificate": {"common_name": "*.example.test"}}),
            ("POST", "/order/certificate/4242/reissue"): FakeResponse(201, {"id": 4242, "certificate_id": 3}),
        }, skip_approval=True)
        c.submit(self.csr_der, "4242")
        self.assertIs(s.calls[-1][3]["skip_approval"], True)

    def test_reissue_refuses_an_order_that_belongs_to_another_name(self):
        c, s = self.client({("GET", "/order/certificate/4242"): FakeResponse(200, {"status": "issued", "certificate": {"common_name": "billing.example.test"}})})
        with self.assertRaises(CaPermanentError) as cm:
            c.submit(self.csr_der, "4242")
        self.assertIn("billing.example.test", str(cm.exception))
        self.assertEqual([x[0] for x in s.calls], ["GET"], "no POST may follow")

    def test_an_expired_order_is_renewed_only_when_buying_is_allowed(self):
        routes = {("GET", "/order/certificate/4242"): FakeResponse(200, {"status": "expired", "certificate": {"common_name": "*.example.test"}})}
        c, s = self.client(dict(routes))
        with self.assertRaises(CaPermanentError) as cm:
            c.submit(self.csr_der, "4242")
        self.assertIn("expired", str(cm.exception))
        routes[("POST", "/order/certificate/ssl_wildcard")] = FakeResponse(201, {"id": 5000, "certificate_id": 1})
        c, s = self.client(dict(routes), allow_new_order=True)
        o = c.submit(self.csr_der, "4242")
        self.assertEqual((o.order_id, o.extra["kind"]), ("5000", "renewal"))
        self.assertEqual(s.calls[-1][3]["renewal_of_order_id"], 4242, "linked to the old order so the history stays in CertCentral")

    def test_status_requires_the_certificate_for_OUR_key(self):
        other_csr = csr_for(rsa.generate_private_key(65537, 2048)).public_bytes(serialization.Encoding.PEM).decode()
        c, s = self.client({
            ("GET", "/order/certificate/9"): [
                FakeResponse(200, {"status": "issued", "certificate": {"id": 5, "csr": other_csr}, "pending_reissue": {"status": "pending"}}),
                FakeResponse(200, {"status": "issued", "certificate": {"id": 6, "csr": self.csr_pem}}),
            ]
        })
        o = CaOrder("9", "2026-11-01T12:00:00Z", {"spki": core.spki_sha256(self.key.public_key())})
        self.assertEqual(c.status(o).state, "pending", "the previous certificate of the order must not be mistaken for the new one")
        st = c.status(o)
        self.assertEqual((st.state, st.certificate_id), ("issued", "6"))

    def test_status_when_the_order_does_not_echo_the_csr(self):
        """No CSR in the order JSON: issued + certificate id is accepted (fetch_chain proves the key), but a pending reissue still waits."""
        c, _ = self.client({
            ("GET", "/order/certificate/9"): [
                FakeResponse(200, {"status": "issued", "certificate": {"id": 5}, "pending_reissue": {"status": "pending"}}),
                FakeResponse(200, {"status": "issued", "certificate": {"id": 6}}),
                FakeResponse(200, {"status": "issued", "certificate": {"id": 7}}),
            ]
        })
        o = CaOrder("9", "2026-11-01T12:00:00Z", {"spki": core.spki_sha256(self.key.public_key()), "kind": "reissue"})
        self.assertEqual(c.status(o).state, "pending", "a reissue that is still pending means the order still shows the previous certificate")
        st = c.status(o)
        self.assertEqual((st.state, st.certificate_id), ("issued", "6"))
        fresh = CaOrder("9", "2026-11-01T12:00:00Z", {"spki": core.spki_sha256(self.key.public_key()), "kind": "new"})
        self.assertEqual(c.status(fresh).state, "issued")

    def test_rejected_order_fails(self):
        c, _ = self.client({("GET", "/order/certificate/9"): FakeResponse(200, {"status": "rejected"})})
        self.assertEqual(c.status(CaOrder("9", "2026-11-01T12:00:00Z", {})).state, "failed")

    def test_pending_states_explain_what_the_order_is_waiting_for(self):
        o = CaOrder("9", "2026-11-01T12:00:00Z", {"spki": "x", "dcv": {"method": "dns-txt-token", "token": "tok123"}})
        c, _ = self.client({("GET", "/order/certificate/9"): [FakeResponse(200, {"status": "needs_approval"}), FakeResponse(200, {"status": "pending"})]})
        st = c.status(o)
        self.assertEqual(st.state, "pending")
        self.assertIn("approve", st.detail)
        st = c.status(o)
        self.assertIn("tok123", st.detail, "the DNS validation token is surfaced so a person or a DNS job can publish it")

    def test_download_for_the_previous_key_is_transient_not_permanent(self):
        """While a reissue is in flight the order can still hand back the OLD certificate. That must wait, not fail forever."""
        other = csr_for(rsa.generate_private_key(65537, 2048))
        bundle = make_ca_bundle()
        old = LocalTestCaClient(lambda: bundle, clock=lambda: T0).fetch_chain(CaOrder("x", "2026-11-01T12:00:00Z"), other.public_bytes(serialization.Encoding.DER))
        old_pem = b"".join(x509.load_der_x509_certificate(d).public_bytes(serialization.Encoding.PEM) for d in old).decode()
        c, s = self.client({
            ("GET", "/order/certificate/9"): FakeResponse(200, {"status": "issued", "certificate": {"id": 6, "csr": self.csr_pem}}),
            ("GET", "/certificate/6/download/format/pem_all"): FakeResponse(200, None, text=old_pem),
        })
        o = CaOrder("9", "2026-11-01T12:00:00Z", {"spki": core.spki_sha256(self.key.public_key())})
        with self.assertRaises(CaTransientError):
            c.fetch_chain(o, self.csr_der)

    def test_fetch_chain_returns_leaf_first_for_our_key(self):
        bundle = make_ca_bundle()
        leaf = LocalTestCaClient(lambda: bundle, clock=lambda: T0).fetch_chain(CaOrder("x", "2026-11-01T12:00:00Z"), self.csr_der)
        pem = b"".join(x509.load_der_x509_certificate(d).public_bytes(serialization.Encoding.PEM) for d in reversed(leaf)).decode()
        c, s = self.client({
            ("GET", "/order/certificate/9"): [
                FakeResponse(200, {"status": "issued", "certificate": {"id": 6, "csr": self.csr_pem}}),
                FakeResponse(200, {"status": "issued", "certificate": {"id": 6, "csr": self.csr_pem}}),
            ],
            ("GET", "/certificate/6/download/format/pem_all"): FakeResponse(200, None, text=pem),
        })
        o = CaOrder("9", "2026-11-01T12:00:00Z", {"spki": core.spki_sha256(self.key.public_key())})
        chain = c.fetch_chain(o, self.csr_der)
        self.assertEqual(x509.load_der_x509_certificate(chain[0]).subject.rfc4514_string(), "CN=*.example.test")
        self.assertEqual(len(chain), 2)

    def test_http_errors_are_classified(self):
        c, _ = self.client({("POST", "/order/certificate/ssl_wildcard"): [FakeResponse(429), FakeResponse(503), FakeResponse(401, {"errors": [{"code": "access_denied", "message": "bad key"}]})]}, allow_new_order=True)
        with self.assertRaises(CaTransientError):
            c.submit(self.csr_der, None)
        with self.assertRaises(CaTransientError):
            c.submit(self.csr_der, None)
        with self.assertRaises(CaPermanentError) as cm:
            c.submit(self.csr_der, None)
        self.assertIn("access_denied", str(cm.exception))
        self.assertNotIn("secret-key", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
