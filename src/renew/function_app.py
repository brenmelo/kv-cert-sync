import logging
import os

import azure.functions as func

from kvrenew.core import build_context, one_line, parse_event_message, reconcile_renewals, renew_certificate
from kvrenew.state import StateConflict  # noqa: F401  (import check at cold start)

logging.getLogger("kvrenew").setLevel(logging.INFO)
logging.getLogger("azure").setLevel(logging.WARNING)

app = func.FunctionApp()
_ctx = None
INGEST_MODE = os.environ.get("INGEST_MODE", "eventgrid").lower()  # eventgrid | queue


def _context():
    global _ctx
    if _ctx is None:
        _ctx = build_context()
    return _ctx


def _handle(event_type: str, data: dict) -> None:
    etype = (event_type or "").rsplit(".", 1)[-1]
    name = data.get("ObjectName")
    if data.get("ObjectType") != "Certificate" or not name or etype != "CertificateNearExpiry":
        logging.info('KVRENEW result=ignored trigger=%s msg="not a near-expiry certificate event"', etype)
        return
    try:
        renew_certificate(name, _context(), trigger=etype)
    except Exception as e:  # noqa: BLE001
        # The host retries the message (and finally parks it in the poison queue); the timer sweep is the safety net and is what
        # raises the alert ("failed-transient"), so a one-off error does not page anyone.
        logging.warning('KVRENEW result=retrying cert=%s trigger=%s error=%s msg="%s"', name, etype, type(e).__name__, one_line(e))
        raise


@app.function_name(name="renew_reconcile")
@app.timer_trigger(schedule="%RENEW_SCHEDULE%", arg_name="timer", run_on_startup=False)
def renew_reconcile(timer: func.TimerRequest) -> None:
    """Polls pending orders and starts renewals that are due. Also the safety net for a missed event."""
    reconcile_renewals(_context(), trigger="timer")


if INGEST_MODE == "queue":

    @app.function_name(name="kv_renew_queue")
    @app.queue_trigger(arg_name="msg", queue_name="%RENEW_QUEUE_NAME%", connection="QueueConn")
    def kv_renew_queue(msg: func.QueueMessage) -> None:
        for ev in parse_event_message(msg.get_body()):
            _handle(ev.get("eventType", ""), ev.get("data") or {})

else:

    @app.function_name(name="kv_renew_event")
    @app.event_grid_trigger(arg_name="event")
    def kv_renew_event(event: func.EventGridEvent) -> None:
        _handle(event.event_type, event.get_json() or {})
