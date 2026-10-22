"""Run a KQL query against the PoC Log Analytics workspace and print the rows.

usage: python la_query.py --file q.kql [--timespan PT2H] [--json out.json]
"""
import argparse
import json
import sys
import urllib.request

from azure.identity import AzureCliCredential

WORKSPACE_ID = None  # resolved from --workspace or evidence\workspace_id.txt


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--file")
    p.add_argument("--query")
    p.add_argument("--workspace", required=True, help="Log Analytics workspace customerId (GUID)")
    p.add_argument("--timespan", default="PT3H")
    p.add_argument("--json")
    a = p.parse_args()
    q = a.query or open(a.file, encoding="utf-8").read()
    tok = AzureCliCredential(process_timeout=90).get_token("https://api.loganalytics.io/.default").token
    req = urllib.request.Request(
        f"https://api.loganalytics.io/v1/workspaces/{a.workspace}/query",
        data=json.dumps({"query": q, "timespan": a.timespan}).encode(),
        headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
    )
    try:
        data = json.load(urllib.request.urlopen(req, timeout=60))
    except urllib.error.HTTPError as e:  # noqa: PERF203
        print(e.read().decode()[:2000], file=sys.stderr)
        return 1
    t = data["tables"][0]
    cols = [c["name"] for c in t["columns"]]
    rows = t["rows"]
    if a.json:
        json.dump([dict(zip(cols, r)) for r in rows], open(a.json, "w", encoding="utf-8"), indent=2)
    print(f"{len(rows)} row(s)")
    for r in rows:
        print(" | ".join("" if v is None else str(v) for v in r))
    return 0


if __name__ == "__main__":
    sys.exit(main())
