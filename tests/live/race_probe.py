"""Two events for ONE certificate that arrive at the same moment must copy it exactly once.

    pip install azure-storage-queue        (this is the only live test that writes to the sync queue)
    python tests/live/race_probe.py --outputs outputs.json --evidence .scratch/race.json --grant-send-role

Why this exists. The end-to-end test found a destination vault that held the same certificate twice. Key Vault had raised a
"new version" event and a "near expiry" event for one certificate within the same second, the Functions host ran the two queue
messages on two threads (host.json: batchSize 4), both threads found the destination empty and both imported the certificate.
The sync now takes a lock per certificate name. This probe makes that situation on purpose and counts the versions.

What it does, all with one throw-away certificate named race-<run>:
    1  imports it at the factory with  kvsync=<one destination>  and waits for the normal copy
    2  deletes and PURGES the copy in that destination, so the next two events find it empty
         (the destination must not have purge protection; with `--dest` pick one that has not)
    3  waits for a safe moment between two timer sweeps (the sweep would copy it too and hide the race)
    4  puts the two events Key Vault would send on the sync queue at the same moment
    5  waits for the copy, waits a further quiet period, counts the versions, and reads the log lines

    C0  the probe could write to the sync queue
    C1  the destination was empty when the two events arrived
    C2  the destination received the certificate
    C3  it holds exactly ONE version of it (two would be the duplicate import)
    C4  the log shows one `copied` and one `converged-noop` for it, both from the two events and none from the timer sweep
        (a `copied` from the timer would mean the race never happened: the run is reported as inconclusive and repeated)

--grant-send-role gives the signed-in user "Storage Queue Data Message Sender" on the sync storage account for the length of the
run and removes it afterwards. Without the flag the role must already be in place.
Only certificates named race-<run> are touched, and they are deleted again.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import sys
import threading
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import edge  # noqa: E402  (shared helpers: say / check / make_pfx / import_policy / thumb / cred)
from alerts_probe import TIMELINE, Env, az, lines, now, stamp, wait_until  # noqa: E402

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError  # noqa: E402

try:
    from azure.storage.queue import QueueClient
except ImportError:  # pragma: no cover
    sys.exit("This probe needs the queue SDK:  pip install azure-storage-queue")

SENDER_ROLE = "Storage Queue Data Message Sender"
SWEEP_SECONDS = 300  # RECONCILE_SCHEDULE is "0 */5 * * * *": the sweep runs at second 0 of every fifth minute (UTC)


def app_setting(env: Env, app: str, key: str) -> str:
    rows = az("functionapp", "config", "appsettings", "list", "--name", app, "--resource-group", env.hub_rg, "--subscription", env.hub_sub)
    return next((r["value"] for r in rows if r["name"] == key), "")


def grant_sender(env: Env, account: str) -> str | None:
    """Give the signed-in user permission to put messages on the queues of `account`. Returns the assignment id to remove later."""
    oid = az("ad", "signed-in-user", "show", "--query", "id")
    scope = f"/subscriptions/{env.hub_sub}/resourceGroups/{env.hub_rg}/providers/Microsoft.Storage/storageAccounts/{account}"
    r = az("role", "assignment", "create", "--assignee-object-id", oid, "--assignee-principal-type", "User", "--role", SENDER_ROLE,
           "--scope", scope, "--subscription", env.hub_sub)
    stamp("temporary role assignment created", role=SENDER_ROLE, account=account)
    return r["id"]


def event(kind: str, env: Env, name: str, props) -> dict:
    """The event Key Vault raises, in the shape Event Grid writes to the queue."""
    vault = edge.vault_name(env.src_uri)
    return {
        "id": str(uuid.uuid4()),
        "topic": f"/subscriptions/{env.hub_sub}/resourceGroups/{env.hub_rg}/providers/Microsoft.KeyVault/vaults/{vault}",
        "subject": name,
        "eventType": f"Microsoft.KeyVault.{kind}",
        "eventTime": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "data": {
            "Id": f"{env.src_uri.rstrip('/')}/certificates/{name}/{props.version}",
            "VaultName": vault, "ObjectType": "Certificate", "ObjectName": name, "Version": props.version,
            "NBF": int(props.not_before.timestamp()) if props.not_before else None,
            "EXP": int(props.expires_on.timestamp()) if props.expires_on else None,
        },
        "dataVersion": "1", "metadataVersion": "1",
    }


def send_together(qc: QueueClient, events: list[dict]) -> list[dict]:
    """Put every event on the queue at the same moment (one thread each, released together)."""
    barrier = threading.Barrier(len(events))
    sent: list[dict] = []
    errors: list[BaseException] = []

    def one(ev: dict) -> None:
        body = base64.b64encode(json.dumps(ev).encode("utf-8")).decode("ascii")  # what Event Grid stores in a Storage queue
        try:
            barrier.wait(30)
            t = time.time()
            qc.send_message(body)
            sent.append({"event": ev["eventType"].rsplit(".", 1)[-1], "put_ms": round((time.time() - t) * 1000)})
        except BaseException as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=one, args=(e,)) for e in events]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    if errors:
        raise errors[0]
    return sent


def versions(client, name: str) -> list[str]:
    try:
        return [v.version for v in client.list_properties_of_certificate_versions(name)]
    except ResourceNotFoundError:
        return []


def purge(client, name: str) -> str:
    """Delete and purge `name`. Returns "purged", or "protected" when the vault keeps deleted objects."""
    client.begin_delete_certificate(name).wait()
    try:
        client.purge_deleted_certificate(name)
    except HttpResponseError as e:
        if "purge protection" in str(e).lower() or e.status_code in (403, 409):
            return "protected"
        raise

    def gone():
        try:
            client.get_deleted_certificate(name)
            return False
        except ResourceNotFoundError:
            return True

    wait_until(gone, 120, 3, "the purge to finish")
    time.sleep(5)
    return "purged"


def wait_for_quiet_sweep() -> None:
    """A sweep copies every opted-in certificate that is missing, which would hide the race. Start just after one has run."""
    to_next = SWEEP_SECONDS - (time.time() % SWEEP_SECONDS)
    if to_next < 75:
        edge.say(f"         the next timer sweep is in {to_next:.0f} s: waiting for it to pass")
        time.sleep(to_next + 10)


def attempt(env: Env, qc: QueueClient, run: str, dest_key: str) -> dict:
    """One try. Returns {'conclusive': bool, 'ok': bool, ...}."""
    dest = env.dests[dest_key]
    dname = env.dest_info[dest_key]["name"]
    name, cn = f"race-{run}", f"race-{run}.example.test"

    pfx, th = edge.make_pfx(cn)
    env.src.import_certificate(name, pfx, policy=edge.import_policy(), tags={"kvsync": dest_key})
    stamp("certificate created at the factory", cert=name, destination=dest_key, thumb=th[:8])
    copied = wait_until(lambda: edge.thumb(dest, name) == th, 420, 10, f"the normal copy into {dname}")
    if not copied:
        edge.check("C2", False, f"the normal copy into {dname} did not arrive within 7 minutes (is the factory healthy?)")
        return {"conclusive": True, "ok": False}
    one_version = len(versions(dest, name)) == 1
    stamp("normal copy arrived", versions=len(versions(dest, name)))

    state = purge(dest, name)
    if state == "protected":
        edge.check("C1", False, f"{dname} has purge protection, so its copy cannot be removed again: run with --dest <another key>")
        return {"conclusive": True, "ok": False}
    empty = not versions(dest, name)
    edge.check("C1", empty and one_version, f"the destination copy was removed and purged, so {dname} is empty when the events arrive")
    if not empty:
        return {"conclusive": True, "ok": False}
    stamp("destination copy purged")

    wait_for_quiet_sweep()
    props = env.src.get_certificate(name).properties
    since = now()
    events = [event("CertificateNewVersionCreated", env, name, props), event("CertificateNearExpiry", env, name, props)]
    sent = send_together(qc, events)
    stamp("two events put on the queue at the same moment", sent=sent)
    edge.check("C0", len(sent) == 2, "both events were written to the sync queue", sent=sent)

    arrived = wait_until(lambda: edge.thumb(dest, name) == th, 240, 3, f"the copy into {dname}")
    t_copy = (now() - since).total_seconds()
    edge.check("C2", bool(arrived), f"{dname} received the certificate {t_copy:.0f} s after the events" if arrived
               else f"{dname} did not receive the certificate within 4 minutes", seconds=round(t_copy))
    if not arrived:
        return {"conclusive": True, "ok": False}

    quiet = 60
    edge.say(f"         quiet period of {quiet} s: a duplicate import, if there is one, lands in this window")
    time.sleep(quiet)
    vs = versions(dest, name)
    edge.check("C3", len(vs) == 1, f"{dname} holds exactly {len(vs)} version(s) of the certificate (expected 1)", versions=vs)

    def log_rows():
        rows = [r for r in lines(env, name, since) if f"dest={dest_key}" in r["Message"]]
        done = [r for r in rows if "result=copied" in r["Message"] or "result=converged-noop" in r["Message"]]
        return rows if len(done) >= 2 else None

    rows = wait_until(log_rows, 420, 20, "the log lines (Log Analytics ingestion takes a few minutes)") or []
    msgs = [r["Message"] for r in rows]
    copied_lines = [m for m in msgs if "result=copied" in m]
    noop_lines = [m for m in msgs if "result=converged-noop" in m]
    by_timer = [m for m in copied_lines if "trigger=timer" in m]
    trig = lambda ms: [m.split("trigger=")[1].split()[0] for m in ms if "trigger=" in m]  # noqa: E731
    if by_timer:
        edge.say("INCONCLUSIVE the timer sweep copied the certificate before the two events were handled; trying again")
        return {"conclusive": False, "ok": False, "copied_by": trig(copied_lines)}
    ok = len(copied_lines) == 1 and len(noop_lines) == 1
    edge.check("C4", ok, f"the log has {len(copied_lines)} `copied` line(s) ({', '.join(trig(copied_lines)) or '-'}) and "
               f"{len(noop_lines)} `converged-noop` line(s) ({', '.join(trig(noop_lines)) or '-'}) for {dname}; expected 1 and 1",
               copied=trig(copied_lines), noop=trig(noop_lines))
    return {"conclusive": True, "ok": len(vs) == 1 and ok}


def clean(env: Env, run: str) -> None:
    name = f"race-{run}"
    for label, c in [("source", env.src), *env.dests.items()]:
        try:
            purge(c, name)
        except Exception as e:  # noqa: BLE001  already gone, or not ours to delete
            edge.say(f"CLEAN     {label}: {type(e).__name__}")
    edge.say(f"CLEAN     {name} deleted")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--outputs", required=True, help="the stack's outputs (`terraform output -json`, or the ARM deployment outputs) saved to a file")
    p.add_argument("--run", default=now().strftime("%H%M%S"), help="keeps the certificate name unique")
    p.add_argument("--dest", default=None, help="key of the destination to use (default: the last one; it must not have purge protection)")
    p.add_argument("--attempts", type=int, default=2, help="how often to repeat when the timer sweep got in the way")
    p.add_argument("--grant-send-role", action="store_true", help=f"give the signed-in user {SENDER_ROLE!r} on the sync storage account for the run")
    p.add_argument("--evidence", default=None, help="write the results as JSON here (the log goes next to it)")
    p.add_argument("--keep", action="store_true", help="do not delete the test certificate afterwards")
    a = p.parse_args()

    env = Env(json.loads(Path(a.outputs).read_text(encoding="utf-8-sig")))
    edge.LOG = Path(a.evidence).with_suffix(".log") if a.evidence else None
    dest_key = a.dest or env.keys[-1]
    if dest_key not in env.dests:
        sys.exit(f"--dest must be one of {env.keys}")

    app = env.apps["sync"]
    queue_uri = app_setting(env, app, "QueueConn__queueServiceUri")
    queue_name = app_setting(env, app, "SYNC_QUEUE_NAME") or "kvsync-events"
    ingest = app_setting(env, app, "INGEST_MODE")
    if ingest != "queue" or not queue_uri:
        sys.exit(f"{app} does not read a queue (INGEST_MODE={ingest!r}); this probe needs the queue ingest mode")
    account = queue_uri.split("//", 1)[1].split(".", 1)[0]
    edge.say(f"=== race probe, run {a.run}: source {edge.vault_name(env.src_uri)}, destination {dest_key}={env.dest_info[dest_key]['name']}, "
             f"queue {queue_name} on {account} ===")

    assignment = None
    used: list[str] = []
    result = {"conclusive": False, "ok": False}
    try:
        if a.grant_send_role:
            assignment = grant_sender(env, account)
        qc = QueueClient(queue_uri, queue_name, credential=edge.cred)

        # A harmless event for something that is not a certificate: the sync logs `ignored`. It also waits out the role replication.
        probe_event = {"id": str(uuid.uuid4()), "eventType": "Microsoft.KeyVault.CertificateNewVersionCreated",
                       "data": {"ObjectType": "Secret", "ObjectName": f"race-{a.run}-access-check", "VaultName": edge.vault_name(env.src_uri)}}
        can_send = wait_until(lambda: qc.send_message(base64.b64encode(json.dumps(probe_event).encode()).decode()) and True,
                              600 if a.grant_send_role else 15, 15, "permission to write to the sync queue")
        if not can_send:
            edge.check("C0", False, f"cannot write to the queue {queue_name}: grant {SENDER_ROLE!r} on {account} or use --grant-send-role")
            return 1

        for n in range(1, a.attempts + 1):
            edge.say(f"--- attempt {n} of {a.attempts}")
            used.append(a.run if n == 1 else f"{a.run}{n}")
            result = attempt(env, qc, used[-1], dest_key)
            if result["conclusive"]:
                break
        if not result["conclusive"]:
            edge.check("C4", False, "every attempt was overtaken by the timer sweep; run it again")
    finally:
        if not a.keep:
            for r in used:
                clean(env, r)
        if assignment:
            az("role", "assignment", "delete", "--ids", assignment, "--subscription", env.hub_sub, check=False)
            stamp("temporary role assignment removed")
        if a.evidence:
            Path(a.evidence).write_text(json.dumps({"run": a.run, "finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                                                    "destination": dest_key, "timeline": TIMELINE, "results": edge.results}, indent=2),
                                        encoding="utf-8")
    edge.say("=== race probe done: " + ("ALL PASSED ===" if not edge.failures and result.get("ok") else f"FAILED: {edge.failures} ==="))
    return 0 if (not edge.failures and result.get("ok")) else 1


if __name__ == "__main__":
    sys.exit(main())
