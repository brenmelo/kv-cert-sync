import base64, datetime as dt, pathlib, sys, types
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src" / "sync"))
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from kvsync import sync

def mk(key):
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "*.example.test")])
    now = dt.datetime.now(dt.timezone.utc)
    return (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now+dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("*.example.test")]), False).sign(key, hashes.SHA256()))

def secret(value, ctype):
    return types.SimpleNamespace(value=value, properties=types.SimpleNamespace(content_type=ctype))

ok = True
def check(label, cond):
    global ok; ok &= bool(cond); print(("PASS " if cond else "FAIL ") + label)

for kind, key in (("RSA-2048", rsa.generate_private_key(65537, 2048)), ("EC-P256", ec.generate_private_key(ec.SECP256R1()))):
    cert = mk(key)
    p12 = pkcs12.serialize_key_and_certificates(b"x", key, cert, None, serialization.NoEncryption())
    m = sync.load_material(secret(base64.b64encode(p12).decode(), "application/x-pkcs12"))
    check(f"{kind} pkcs12 parsed, thumbprint matches cert", m.thumbprint == cert.fingerprint(hashes.SHA1()).hex().upper())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()) + cert.public_bytes(serialization.Encoding.PEM)
    m2 = sync.load_material(secret(pem.decode(), "application/x-pem-file"))
    check(f"{kind} PEM parsed, same key id as PKCS12", m2.key_id == m.key_id)
    pol = sync._import_policy(m)
    check(f"{kind} import policy derived from key (exportable, Unknown issuer)", pol.exportable and pol.issuer_name == "Unknown")

# mismatched key/cert must be rejected
k1, k2 = rsa.generate_private_key(65537, 2048), rsa.generate_private_key(65537, 2048)
bad = pem_bad = k2.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()) + mk(k1).public_bytes(serialization.Encoding.PEM)
try:
    sync.load_material(secret(bad.decode(), "application/x-pem-file")); check("mismatched key/cert rejected", False)
except sync.PermanentSyncError as e:
    check(f"mismatched key/cert rejected ({e})", True)

# cert with no private key (non-exportable) must be rejected
try:
    sync.load_material(secret(mk(k1).public_bytes(serialization.Encoding.PEM).decode(), "application/x-pem-file")); check("no-private-key rejected", False)
except sync.PermanentSyncError as e:
    check(f"no-private-key rejected ({e})", True)

dests = [sync.Dest("dest-a","https://a/"), sync.Dest("dest-b","https://b/")]
check("selector all -> 2 targets", len(sync._select_targets("all", dests)) == 2)
check("selector 'dest-b' -> 1 target", [d.key for d in sync._select_targets("dest-b", dests)] == ["dest-b"])
check("selector unknown -> 0 targets", sync._select_targets("nope", dests) == [])

# ---- the copy decision against fake vaults (no network): who may be overwritten, who may not
from azure.core.exceptions import ResourceNotFoundError

_key = rsa.generate_private_key(65537, 2048)
_cert = mk(_key)
_p12 = pkcs12.serialize_key_and_certificates(b"x", _key, _cert, None, serialization.NoEncryption())
M = sync.load_material(secret(base64.b64encode(_p12).decode(), "application/x-pkcs12"))
OTHER = "AA" * 20


class FakeVault:
    def __init__(self, tags=None, thumb=None):
        self.existing = None if tags is None else types.SimpleNamespace(
            properties=types.SimpleNamespace(version="old", x509_thumbprint=bytes.fromhex(thumb or OTHER), tags=tags))
        self.imported = []

    def get_certificate(self, name):
        if self.existing is None:
            raise ResourceNotFoundError("not found")
        return self.existing

    def import_certificate(self, name, raw, enabled=True, tags=None, policy=None):
        self.imported.append(tags)
        return types.SimpleNamespace(properties=types.SimpleNamespace(version=f"new{len(self.imported)}"))

    def get_certificate_version(self, name, version):
        return types.SimpleNamespace(properties=types.SimpleNamespace(x509_thumbprint=bytes.fromhex(M.thumbprint)),
                                     cer=M.cert.public_bytes(serialization.Encoding.DER))


def run_copy(vault):
    ctx = sync.Context(source_uri="https://kv-src-x.vault.azure.net/", dests=[], credential=None)
    ctx._certs["https://d/"] = vault
    props = types.SimpleNamespace(version="srcv1")
    return sync._copy(ctx, sync.Dest("d", "https://d/"), "c", M, props, {"kvsync": "all", "kvrenew": "on", "app": "demo"},
                      dict(cert="c", trigger="test", event_version=None))


v = FakeVault()
r = run_copy(v)
check("new name: copied", r["result"] == "copied" and len(v.imported) == 1)
check("replica tags: origin set, kvsync/kvrenew removed, app kept",
      v.imported[0].get("kvsync-origin") == "kv-src-x" and "kvsync" not in v.imported[0] and "kvrenew" not in v.imported[0] and v.imported[0].get("app") == "demo")
v = FakeVault(tags={"owner": "someone"})
r = run_copy(v)
check("unmanaged certificate with the same name: refused, untouched", r["result"] == "failed-permanent" and not v.imported and "kvsync-origin=kv-src-x" in r["msg"])
v = FakeVault(tags={"kvsync-origin": "kv-src-OTHER"})
r = run_copy(v)
check("replica of ANOTHER source vault: refused, untouched", r["result"] == "failed-permanent" and not v.imported and "kv-src-OTHER" in r["msg"])
v = FakeVault(tags={"kvsync-origin": "kv-src-x"}, thumb=M.thumbprint)
r = run_copy(v)
check("own replica, same thumbprint: nothing to do", r["result"] == "converged-noop" and not v.imported)
v = FakeVault(tags={"kvsync-origin": "kv-src-x"})
r = run_copy(v)
check("own replica, older thumbprint: new version imported", r["result"] == "copied" and len(v.imported) == 1)
v = FakeVault(tags={"app": "adopted-by-hand", "kvsync-origin": "kv-src-x"})
r = run_copy(v)
check("adopted by hand (origin tag = this source): overwritten with a new version", r["result"] == "copied" and len(v.imported) == 1)

# ---- a copy that is current but close to expiry is reported (replaces Key Vault's fixed 30-day near-expiry event)
import logging, os


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append((record.levelno, record.getMessage()))


_cap = _Capture()
sync.log.addHandler(_cap)
sync.log.setLevel(logging.DEBUG)


def lines_for(vault, warn_days=None):
    _cap.lines.clear()
    if warn_days is None:
        os.environ.pop("REPLICA_WARN_DAYS", None)
    else:
        os.environ["REPLICA_WARN_DAYS"] = str(warn_days)
    try:
        run_copy(vault)
    finally:
        os.environ.pop("REPLICA_WARN_DAYS", None)
    return list(_cap.lines)


got = lines_for(FakeVault())
check("30-day certificate, default threshold (7 days): copied, every line reports days_left, no expiry warning",
      any("result=copied" in m and "days_left=" in m for _, m in got) and not any("replica-expiring" in m for _, m in got))
got = lines_for(FakeVault(), warn_days=45)
warn = [(lv, m) for lv, m in got if "KVSYNC result=replica-expiring" in m]
check("30-day certificate, threshold 45 days: a WARNING 'KVSYNC result=replica-expiring' with days_left and warn_days",
      len(warn) == 1 and warn[0][0] == logging.WARNING and "days_left=" in warn[0][1] and "warn_days=45.0" in warn[0][1])
got = lines_for(FakeVault(tags={"kvsync-origin": "kv-src-x"}, thumb=M.thumbprint), warn_days=45)
check("already converged but close to expiry: still reported (the sweep sees it every time)",
      any("result=converged-noop" in m for _, m in got) and any("KVSYNC result=replica-expiring" in m for _, m in got))
got = lines_for(FakeVault(tags={"kvsync-origin": "kv-src-x"}, thumb=M.thumbprint), warn_days="not-a-number")
check("unreadable REPLICA_WARN_DAYS falls back to 7 days (no warning for 30 days left)",
      not any("replica-expiring" in m for _, m in got))

# ---- failures are reported in the standard one-line format and one bad certificate does not stop the sweep
from azure.core.exceptions import HttpResponseError


class FakeSource:
    def list_properties_of_certificates(self):
        T = types.SimpleNamespace
        return [T(name="a", enabled=True, tags={"kvsync": "all"}), T(name="b", enabled=True, tags={"kvsync": "all"}),
                T(name="r", enabled=True, tags={"kvsync": "all", "kvsync-origin": "kv-src-x"}),  # a replica: never walked
                T(name="n", enabled=True, tags={}), T(name="d", enabled=False, tags={"kvsync": "all"})]


sweep_ctx = sync.Context(source_uri="https://kv-src-x.vault.azure.net/", dests=[], credential=None)
sweep_ctx._certs[sweep_ctx.source_uri] = FakeSource()
visited = []


def fake_sync(name, ctx, *, trigger, event_version=None):
    visited.append(name)
    if name == "a":
        raise HttpResponseError("(Forbidden) Public network access is disabled\nCode: Forbidden\nInner error: {\n  'code': 'ForbiddenByConnection'\n}")
    return [{"result": "converged-noop"}]


_orig = sync.sync_certificate
sync.sync_certificate = fake_sync
_cap.lines.clear()
try:
    sync.reconcile(sweep_ctx)
    raised = False
except RuntimeError as e:
    raised = "1 certificate(s) failed" in str(e)
finally:
    sync.sync_certificate = _orig
sweep = [(lv, m) for lv, m in _cap.lines]
fail = [m for lv, m in sweep if "KVSYNC result=failed-transient" in m]
check("a sweep with one failing certificate still visits the others, skips replicas / untagged / disabled, and raises at the end",
      visited == ["a", "b"] and raised)
check("the failure is ONE line with result, cert, trigger, error type and the reason (no newlines)",
      len(fail) == 1 and "\n" not in fail[0] and "cert=a" in fail[0] and "trigger=timer" in fail[0]
      and "error=HttpResponseError" in fail[0] and "ForbiddenByConnection" in fail[0])
check("the sweep still reports completion with the failure count (the heartbeat rule keys on it)",
      any("KVSYNC result=reconcile-complete" in m and "failures=1" in m and "seen=2" in m for _, m in sweep))
_cap.lines.clear()
sync.report_failure("c", "CertificateNewVersionCreated", RuntimeError("rotation in flight"), result="retrying", level=logging.WARNING, event_version="v9")
check("an event-path failure is logged as 'retrying' at WARNING (the failure alert keys on the sweep, so a one-off race is not paged)",
      len(_cap.lines) == 1 and _cap.lines[0][0] == logging.WARNING and "KVSYNC result=retrying" in _cap.lines[0][1]
      and "failed" not in _cap.lines[0][1] and "event_version=v9" in _cap.lines[0][1])
sync.log.removeHandler(_cap)


# ---- one unreachable destination does not stop the copy to the others
class BrokenVault:
    def get_certificate(self, name):
        raise HttpResponseError("(Forbidden) Client address is not authorized and caller is not a trusted service.\nCode: Forbidden\nInner error: {\n  'code': 'ForbiddenByFirewall'\n}")


class SourceVault:
    def get_certificate(self, name):
        props = types.SimpleNamespace(version="srcv1", tags={"kvsync": "all", "app": "demo"}, enabled=True, x509_thumbprint=bytes.fromhex(M.thumbprint))
        return types.SimpleNamespace(cer=M.cert.public_bytes(serialization.Encoding.DER), properties=props)

    def get_certificate_policy(self, name):
        return types.SimpleNamespace(exportable=True)


class SourceSecrets:
    def get_secret(self, name, version):
        return secret(base64.b64encode(_p12).decode(), "application/x-pkcs12")


def two_destinations(a, b):
    c = sync.Context(source_uri="https://kv-src-x.vault.azure.net/", dests=[sync.Dest("a", "https://a/"), sync.Dest("b", "https://b/")], credential=None)
    c._certs[c.source_uri], c._secrets[c.source_uri] = SourceVault(), SourceSecrets()
    c._certs["https://a/"], c._certs["https://b/"] = a, b
    return c


def run_sync(a, b):
    try:
        sync.sync_certificate("c", two_destinations(a, b), trigger="timer")
        return None
    except sync.DestinationError as e:
        return e


sync.log.addHandler(_cap)
b_ok = FakeVault()
err = run_sync(BrokenVault(), b_ok)
check("destination A unreachable: destination B still receives the certificate, and the failure is raised AFTER every destination was tried",
      err is not None and [k for k, _ in err.failures] == ["a"] and len(b_ok.imported) == 1)
a_ok = FakeVault()
err = run_sync(a_ok, BrokenVault())
check("destination B unreachable: destination A is updated as well (the order does not matter)",
      err is not None and [k for k, _ in err.failures] == ["b"] and len(a_ok.imported) == 1)
a_ok, b_ok = FakeVault(), FakeVault()
check("both destinations healthy: no error, both updated", run_sync(a_ok, b_ok) is None and len(a_ok.imported) == 1 and len(b_ok.imported) == 1)
err = run_sync(BrokenVault(), BrokenVault())
check("both destinations unreachable: ONE error that names both", err is not None and sorted(k for k, _ in err.failures) == ["a", "b"]
      and "dest=a" in str(err) and "dest=b" in str(err))
_cap.lines.clear()
sync.report_failure("c", "timer", err)
two = [m for _, m in _cap.lines]
check("a failure line per failed destination, each with dest=, error type and the reason, on one line",
      len(two) == 2 and all("KVSYNC result=failed-transient" in m and "\n" not in m and "error=HttpResponseError" in m and "ForbiddenByFirewall" in m for m in two)
      and any("dest=a" in m for m in two) and any("dest=b" in m for m in two))
sync.log.removeHandler(_cap)

# ---- two events for ONE certificate that arrive together must import it ONCE
# (found in the live end-to-end run: a new-version event and a near-expiry event were handled on two threads at the same second,
# and each destination ended up holding the same certificate twice)
import threading, time


class StatefulVault(FakeVault):
    """A destination that remembers what was imported and is slow to import, so two overlapping copies would both find it empty."""

    def __init__(self):
        super().__init__()
        self.guard = threading.Lock()

    def get_certificate(self, name):
        with self.guard:
            return super().get_certificate(name)

    def import_certificate(self, name, raw, enabled=True, tags=None, policy=None):
        time.sleep(0.3)
        with self.guard:
            self.imported.append(tags)
            version = f"new{len(self.imported)}"
            self.existing = types.SimpleNamespace(
                properties=types.SimpleNamespace(version=version, x509_thumbprint=bytes.fromhex(M.thumbprint), tags=tags))
            return types.SimpleNamespace(properties=types.SimpleNamespace(version=version))


def run_together(a, b, triggers):
    ctx = two_destinations(a, b)
    barrier = threading.Barrier(len(triggers))
    results, errors = {}, []

    def one(trigger):
        try:
            barrier.wait()
            results[trigger] = sync.sync_certificate("c", ctx, trigger=trigger)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=one, args=(t,)) for t in triggers]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    return results, errors


a, b = StatefulVault(), StatefulVault()
results, errors = run_together(a, b, ["CertificateNewVersionCreated", "CertificateNearExpiry"])
check("two events for one certificate at the same moment: no error", not errors and len(results) == 2)
check("two events for one certificate at the same moment: each destination imports it exactly once", len(a.imported) == 1 and len(b.imported) == 1)
check("one event copies, the other finds both destinations already current",
      sorted(r["result"] for rs in results.values() for r in rs) == ["converged-noop"] * 2 + ["copied"] * 2)
check("one lock per certificate name; two names never wait for each other",
      sync._cert_lock("x") is sync._cert_lock("x") and sync._cert_lock("x") is not sync._cert_lock("y"))

print("\nALL PASS" if ok else "\nFAILURES")
import unittest  # noqa: E402  (the checks above run at import time; this wrapper lets `unittest discover` report them)


class SyncOffline(unittest.TestCase):
    def test_all_checks_passed(self):
        self.assertTrue(ok, "one or more offline sync checks failed (see the FAIL lines above)")


if __name__ == "__main__":
    sys.exit(0 if ok else 1)
