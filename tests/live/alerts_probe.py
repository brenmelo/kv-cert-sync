"""The alert rules, proven by breaking things on purpose and watching the alerts fire, reach a mailbox and clear.

    terraform -chdir=terraform/poc output -json > outputs.json
    python tests/live/alerts_probe.py --outputs outputs.json --scenario failure   --evidence .scratch/alerts-failure.json
    python tests/live/alerts_probe.py --outputs outputs.json --scenario expiring  --evidence .scratch/alerts-expiring.json
    python tests/live/alerts_probe.py --outputs outputs.json --scenario heartbeat --evidence .scratch/alerts-heartbeat.json
    python tests/live/alerts_probe.py --outputs outputs.json --scenario list

failure    A destination vault becomes unreachable (public network access disabled, which is what an Azure Policy that
           enforces "no public access on Key Vaults" does to a function that still calls over the internet).
           F0 v1 of a test certificate reaches both destinations      F1 the destination really refuses calls
           F2 v2 still reaches the OTHER destination (one broken destination does not stop the rest)
           F3 the sweep logs ONE standard line per failed destination (result, cert, dest, error type, reason)
           F4 the failure alert fires      F5 the unreachable destination kept serving the previous version
           F6 after the unblock the queue's own retry (or, later, the timer sweep) copies v2 with no manual step
           F7 the alert resolves by itself
expiring   A copy with 3 days left although the sync is up to date.
           E0 copied      E1 'replica-expiring' lines for every destination      E2 the severity-1 alert fires
           E3 resolves after the certificate is gone (the rule looks back one hour; use --resolve-wait-min 0 to skip waiting)
heartbeat  The renewal function stops (stopped, throttled, cannot start): the rule that looks for a completed sweep fires.
           H0 the app is stopped      H1 the heartbeat alert fires      H2 after the restart the sweeps resume and the alert clears
           (the rule looks back one hour and is evaluated every 15 minutes, so this takes about 90 minutes)

The mail (one when an alert fires, one when it clears) is not checked here: look in the mailbox of the action group.
Whatever happens, the destination is re-enabled and the renewal function is started again before the script exits.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import edge  # noqa: E402  (shared helpers: say / check / make_pfx / import_policy / thumb / cred)
from abac_probe import la, out_value  # noqa: E402

from azure.keyvault.certificates import CertificateClient  # noqa: E402

ARM = "https://management.azure.com"
TIMELINE: list[dict] = []


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def stamp(event: str, **detail) -> None:
    TIMELINE.append({"t": now().strftime("%Y-%m-%dT%H:%M:%SZ"), "event": event, **detail})
    edge.say(f"TIME     {event}" + (f"  {detail}" if detail else ""))


def parse_ts(s):
    if not s:
        return None
    return dt.datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", s.replace("Z", "+00:00")))


def az(*args: str, check: bool = True):
    p = subprocess.run(["az.cmd", *args, "-o", "json"], capture_output=True, text=True)
    if p.returncode and check:
        raise RuntimeError(f"az {' '.join(args[:3])} failed: {p.stderr.strip()[:500]}")
    return json.loads(p.stdout) if p.stdout.strip() else None


def wait_until(fn, timeout_s: float, every_s: float, label: str):
    """Poll `fn` until it returns something truthy (returned) or the time is up (None)."""
    deadline, last_say = time.time() + timeout_s, 0.0
    while True:
        try:
            v = fn()
        except Exception as e:  # noqa: BLE001  a throttled or lagging API must not end a 90-minute test
            v = None
            if time.time() - last_say > 120:
                edge.say(f"         {label}: {type(e).__name__}: {' '.join(str(e).split())[:120]}")
        if v:
            return v
        if time.time() > deadline:
            return None
        if time.time() - last_say > 120:
            edge.say(f"         waiting for {label} ...")
            last_say = time.time()
        time.sleep(every_s)


class Env:
    def __init__(self, out: dict) -> None:
        src = out_value(out, "source_vault")
        self.src_uri, self.hub_sub = src["uri"], src["subscription"]
        self.dest_info = out_value(out, "destination_vaults")
        self.keys = sorted(self.dest_info)
        self.workspace = out_value(out, "log_analytics_customer_id")
        self.hub_rg = out_value(out, "resource_groups")["hub"]
        self.apps = out_value(out, "function_apps")
        self.src = CertificateClient(self.src_uri, edge.cred)
        self.dests = {k: CertificateClient(self.dest_info[k]["uri"], edge.cred) for k in self.keys}


def alerts(env: Env, rule_prefix: str, since: dt.datetime) -> list[dict]:
    """Alert instances of the rules whose name starts with `rule_prefix` that started after `since` (Azure Monitor alerts API)."""
    token = edge.cred.get_token(ARM + "/.default").token
    url = (f"{ARM}/subscriptions/{env.hub_sub}/providers/Microsoft.AlertsManagement/alerts"
           "?api-version=2019-05-05-preview&timeRange=1d&pageCount=100&sortBy=startDateTime&sortOrder=desc")
    rows: list[dict] = []
    while url:
        data = json.load(urllib.request.urlopen(urllib.request.Request(url, headers={"Authorization": "Bearer " + token}), timeout=60))
        rows += data.get("value", [])
        url = data.get("nextLink")
    out = []
    for r in rows:
        e = r["properties"]["essentials"]
        rule = (e.get("alertRule") or "").rsplit("/", 1)[-1]
        started = parse_ts(e.get("startDateTime"))
        if not rule.startswith(rule_prefix) or (started and started < since):
            continue
        out.append(dict(id=r["name"], rule=rule, severity=e.get("severity"), state=e.get("alertState"),
                        condition=e.get("monitorCondition"), started=e.get("startDateTime"),
                        resolved=e.get("monitorConditionResolvedDateTime"), modified=e.get("lastModifiedDateTime")))
    return out


def alert_in(env: Env, prefix: str, since: dt.datetime, condition: str):
    return lambda: next((x for x in alerts(env, prefix, since) if x["condition"] == condition), None)


def lines(env: Env, cert: str, since: dt.datetime) -> list[dict]:
    q = (f'AppTraces | where TimeGenerated > datetime({since:%Y-%m-%dT%H:%M:%SZ}) | where Message contains "KVSYNC result=" '
         f'and Message contains "cert={cert}" | project TimeGenerated, SeverityLevel, Message | order by TimeGenerated asc')
    return la(env.workspace, q, "PT6H")


def try_thumb(client, name):
    try:
        return edge.thumb(client, name), None
    except Exception as e:  # noqa: BLE001  403 from a vault that refuses the caller
        return None, " ".join(str(e).split())[:200]


def set_public_access(info: dict, enabled: bool) -> None:
    rg = info["id"].split("/")[4]
    az("keyvault", "update", "--name", info["name"], "--resource-group", rg, "--subscription", info["subscription"],
       "--public-network-access", "Enabled" if enabled else "Disabled")


def site_state(env: Env, app: str) -> str | None:
    """`az functionapp show` leaves `state` empty for Flex Consumption apps; the ARM resource has it."""
    r = az("rest", "--method", "get", "--url",
           f"{ARM}/subscriptions/{env.hub_sub}/resourceGroups/{env.hub_rg}/providers/Microsoft.Web/sites/{app}?api-version=2024-04-01",
           "--query", "properties.state")
    return r


def delete_everywhere(env: Env, name: str) -> None:
    for label, c in [("source", env.src), *env.dests.items()]:
        try:
            c.begin_delete_certificate(name).wait()
        except Exception as e:  # noqa: BLE001  already gone, or not ours to delete
            edge.say(f"CLEAN     {label}: {type(e).__name__}")
    edge.say(f"CLEAN     {name} deleted (soft-deleted; purge protection keeps the name reserved in some vaults)")


# ------------------------------------------------------------------------------------------------------- failure
def scenario_failure(env: Env, a) -> None:
    name, tags = f"al-{a.run}", {"kvsync": "all", "purpose": "alerts-probe"}
    broken, other = env.keys[0], env.keys[1]
    info, bclient, oclient = env.dest_info[broken], env.dests[broken], env.dests[env.keys[1]]
    t_start = now()
    before = alerts(env, "alert-kvsync-failures-", t_start - dt.timedelta(days=1))
    edge.say(f"INFO      failure alerts already on record (last 24 h): {[(x['condition'], x['started']) for x in before]}")
    blocked = False
    try:
        pfx1, th1 = edge.make_pfx(f"{name}.example.test")
        env.src.import_certificate(name, pfx1, policy=edge.import_policy(), tags=tags)
        stamp("v1 imported at the source", thumb=th1[:8])
        ok = wait_until(lambda: all(edge.thumb(c, name) == th1 for c in env.dests.values()), 600, 20, "v1 in every destination")
        edge.check("F0", bool(ok), "baseline: v1 reached every destination before anything was broken")
        if not ok:
            return

        set_public_access(info, False)
        blocked = True
        stamp(f"destination {broken} ({info['name']}): public network access DISABLED")
        err = wait_until(lambda: try_thumb(bclient, name)[1], 420, 15, "the block to take effect")
        edge.check("F1", bool(err), f"destination {broken} refuses data-plane calls (the operator is refused too)", error=err)

        pfx2, th2 = edge.make_pfx(f"{name}.example.test")
        env.src.import_certificate(name, pfx2, policy=edge.import_policy(), tags=tags)
        t_v2 = now()
        stamp("v2 imported at the source (a rotation)", thumb=th2[:8])
        ok = wait_until(lambda: edge.thumb(oclient, name) == th2, 600, 20, f"v2 in destination {other}")
        stamp(f"destination {other} holds v2" if ok else f"destination {other} did NOT receive v2")
        edge.check("F2", bool(ok), f"v2 reached destination {other} although destination {broken} is unreachable "
                                   "(one broken destination does not stop the others)")

        def failed_lines():
            rows = [r for r in lines(env, name, t_v2 - dt.timedelta(minutes=1))
                    if "result=failed-transient" in r["Message"] and f"dest={broken}" in r["Message"]]
            return rows or None

        rows = wait_until(failed_lines, 720, 30, "a failed-transient line from the sweep")
        first = rows[0] if rows else None
        edge.check("F3", bool(first) and "error=" in first["Message"] and "\n" not in first["Message"],
                   "the sweep logged one standard line per failed destination: result, cert, trigger, dest, error type, reason",
                   sample=(first["Message"][:420] if first else None))
        if first:
            stamp("first failed-transient line", at=first["TimeGenerated"])
        retrying = [r for r in lines(env, name, t_v2 - dt.timedelta(minutes=1)) if "result=retrying" in r["Message"]]
        edge.say(f"INFO      the event path logged {len(retrying)} 'retrying' line(s) (WARNING; the host retries the queue message)")

        fired = wait_until(alert_in(env, "alert-kvsync-failures-", t_start, "Fired"), a.fire_wait_min * 60, 30, "the failure alert to fire")
        edge.check("F4", bool(fired), "the failure alert FIRED", alert=fired)
        if fired:
            stamp("alert fired", started=fired["started"], severity=fired["severity"])

        set_public_access(info, True)
        blocked = False
        t_heal = now()
        stamp(f"destination {broken}: public network access re-enabled")
        served = wait_until(lambda: (try_thumb(bclient, name)[0] or None), 420, 5, "the destination to answer again")
        stamp(f"destination {broken} answers again", serving=(served or "")[:8])
        if served == th1:
            edge.check("F5", True, f"destination {broken} had kept serving the PREVIOUS version (v1) all along; nothing was half-written")
        else:
            edge.say(f"INFO      F5 not observable: destination {broken} already served {str(served)[:8]} when it first answered "
                     "(a retry or the sweep got there before the read)")
        ok = wait_until(lambda: edge.thumb(bclient, name) == th2, 720, 15, f"destination {broken} to follow")
        edge.check("F6", bool(ok), "self-heal: after the unblock the host's retry of the queued message (or the next sweep) "
                                   "copied v2, with no replay and no manual step")
        if ok:
            stamp(f"destination {broken} converged to v2", after_unblock_s=int((now() - t_heal).total_seconds()))

        if a.resolve_wait_min > 0:
            res = wait_until(alert_in(env, "alert-kvsync-failures-", t_start, "Resolved"), a.resolve_wait_min * 60, 60,
                             "the failure alert to resolve")
            edge.check("F7", bool(res), "the alert resolved by itself once the failures stopped (stateful rule: one mail when it "
                                        "fires and one when it clears)", alert=res)
            if res:
                stamp("alert resolved", at=res["resolved"])
        else:
            edge.say("INFO      F7 skipped (--resolve-wait-min 0); run --scenario list later")
    finally:
        if blocked:
            set_public_access(info, True)
            edge.say(f"CLEAN     destination {broken} public network access re-enabled (the script ended early)")
        if not a.keep:
            delete_everywhere(env, name)


# ------------------------------------------------------------------------------------------------------- expiring
def scenario_expiring(env: Env, a) -> None:
    name, tags = f"ex-{a.run}", {"kvsync": "all", "purpose": "alerts-probe"}
    t_start = now()
    try:
        pfx, th = edge.make_pfx(f"{name}.example.test", days=3)
        env.src.import_certificate(name, pfx, policy=edge.import_policy(), tags=tags)
        stamp("3-day certificate imported at the source", thumb=th[:8])
        ok = wait_until(lambda: all(edge.thumb(c, name) == th for c in env.dests.values()), 600, 20, "the copy")
        edge.check("E0", bool(ok), "a certificate with 3 days left is copied to every destination")

        def warned():
            w = [r for r in lines(env, name, t_start - dt.timedelta(minutes=1)) if "result=replica-expiring" in r["Message"]]
            seen = {m.group(1) for r in w if (m := re.search(r"dest=(\w+)", r["Message"]))}
            return w if seen >= set(env.keys) else None

        w = wait_until(warned, 600, 30, "replica-expiring lines for every destination")
        edge.check("E1", bool(w), "the sync logged 'replica-expiring' (WARNING) for every destination, with days_left and warn_days",
                   sample=(w[0]["Message"][:300] if w else None))
        fired = wait_until(alert_in(env, "alert-kvsync-replica-expiring-", t_start, "Fired"), a.fire_wait_min * 60, 30, "the alert to fire")
        edge.check("E2", bool(fired) and fired["severity"] == "Sev1", "the severity-1 'about to expire' alert FIRED", alert=fired)
        if fired:
            stamp("alert fired", started=fired["started"], severity=fired["severity"])
    finally:
        if not a.keep:
            delete_everywhere(env, name)
    if a.resolve_wait_min > 0:
        res = wait_until(alert_in(env, "alert-kvsync-replica-expiring-", t_start, "Resolved"), a.resolve_wait_min * 60, 60, "the alert to resolve")
        edge.check("E3", bool(res), "the alert resolved by itself after the certificate was gone (the rule looks back one hour)", alert=res)
        if res:
            stamp("alert resolved", at=res["resolved"])
    else:
        edge.say("INFO      E3 skipped (--resolve-wait-min 0); run --scenario list later")


# ------------------------------------------------------------------------------------------------------- heartbeat
def scenario_heartbeat(env: Env, a) -> None:
    app = env.apps["renew"]
    t_start = now()
    last = la(env.workspace, 'AppTraces | where Message contains "KVRENEW result=reconcile-complete" '
                             '| summarize last_sweep = max(TimeGenerated)', "PT3H")
    edge.say(f"INFO      last completed renewal sweep before the test: {last[0]['last_sweep'] if last else 'none in 3 h'}")
    stopped = False
    try:
        az("functionapp", "stop", "--name", app, "--resource-group", env.hub_rg, "--subscription", env.hub_sub)
        stopped = True
        stamp(f"{app} stopped")
        state = site_state(env, app)
        edge.check("H0", state == "Stopped", f"{app} is stopped", state=state)
        fired = wait_until(alert_in(env, "alert-kvrenew-heartbeat-", t_start, "Fired"), a.heartbeat_wait_min * 60, 120,
                           "the heartbeat alert to fire")
        edge.check("H1", bool(fired), "the heartbeat alert FIRED (no completed renewal sweep for an hour)", alert=fired)
        if fired:
            stamp("alert fired", started=fired["started"], severity=fired["severity"])
    finally:
        if stopped:
            az("functionapp", "start", "--name", app, "--resource-group", env.hub_rg, "--subscription", env.hub_sub)
            stamp(f"{app} started again")
    t_up = now()
    sweep = wait_until(lambda: la(env.workspace, f'AppTraces | where TimeGenerated > datetime({t_up:%Y-%m-%dT%H:%M:%SZ}) '
                                                 'and Message contains "KVRENEW result=reconcile-complete"', "PT3H") or None,
                       900, 30, "the first sweep after the restart")
    res = wait_until(alert_in(env, "alert-kvrenew-heartbeat-", t_start, "Resolved"), a.resolve_wait_min * 60, 60, "the alert to resolve")
    edge.check("H2", bool(sweep) and bool(res), "after the restart the sweeps resumed and the alert cleared by itself",
               first_sweep=(sweep[0]["TimeGenerated"] if sweep else None), alert=res)
    if res:
        stamp("alert resolved", at=res["resolved"])


# ------------------------------------------------------------------------------------------------------- main
def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--outputs", required=True, help="`terraform output -json` of the stack, saved to a file")
    p.add_argument("--scenario", required=True, choices=["failure", "expiring", "heartbeat", "list"])
    p.add_argument("--run", default=now().strftime("%H%M"), help="keeps certificate names unique")
    p.add_argument("--fire-wait-min", type=int, default=35, help="how long to wait for an alert to fire")
    p.add_argument("--resolve-wait-min", type=int, default=120,
                   help="how long to wait for it to resolve (0 = do not wait). A stateful rule needs its look-back window "
                        "plus three clean evaluations: allow 30 min for 'failures' and 105 min for 'expiring'")
    p.add_argument("--heartbeat-wait-min", type=int, default=110, help="how long the renewal app stays stopped, at most")
    p.add_argument("--evidence", default=None, help="write the results as JSON here (the log goes next to it)")
    p.add_argument("--keep", action="store_true", help="do not delete the test certificates afterwards")
    a = p.parse_args()

    env = Env(json.loads(Path(a.outputs).read_text(encoding="utf-8-sig")))
    edge.LOG = Path(a.evidence).with_suffix(".log") if a.evidence else None

    if a.scenario == "list":
        for x in sorted(alerts(env, "alert-", now() - dt.timedelta(days=1)), key=lambda r: r["started"] or ""):
            print(f"{x['started']}  {x['rule']:<40} {x['severity']}  {x['condition']:<9} resolved={x['resolved']}")
        return 0

    edge.say(f"=== alert probe '{a.scenario}', run {a.run}: source {env.src_uri}, destinations "
             + ", ".join(f"{k}={env.dest_info[k]['name']}" for k in env.keys) + " ===")
    {"failure": scenario_failure, "expiring": scenario_expiring, "heartbeat": scenario_heartbeat}[a.scenario](env, a)
    if a.evidence:
        Path(a.evidence).write_text(json.dumps({"run": a.run, "scenario": a.scenario, "timeline": TIMELINE, "results": edge.results}, indent=2),
                                    encoding="utf-8")
    edge.say(f"=== alert probe '{a.scenario}' done: " + ("ALL PASSED ===" if not edge.failures else f"FAILED: {edge.failures} ==="))
    return 1 if edge.failures else 0


if __name__ == "__main__":
    sys.exit(main())
