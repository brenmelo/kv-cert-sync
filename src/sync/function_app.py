import logging
import os

import azure.functions as func

from kvsync.sync import build_context, parse_event_message, reconcile, report_failure, sync_certificate

logging.getLogger("kvsync").setLevel(logging.INFO)
logging.getLogger("azure").setLevel(logging.WARNING)

app = func.FunctionApp()
_ctx = None

# eventgrid : Event Grid pushes events to the function over HTTPS (the function must be reachable by Event Grid).
# queue     : Event Grid writes events to a Storage Queue and the function pulls them (works when the function is private).
INGEST_MODE = os.environ.get("INGEST_MODE", "eventgrid").lower()


def _context():
    global _ctx
    if _ctx is None:
        _ctx = build_context()
    return _ctx


def _handle(event_type: str, data: dict) -> None:
    etype = (event_type or "").rsplit(".", 1)[-1]
    name = data.get("ObjectName")
    vault = data.get("VaultName")
    ctx = _context()

    if data.get("ObjectType") != "Certificate" or not name:
        logging.info('KVSYNC result=ignored trigger=%s msg="not a certificate event"', etype)
        return
    if vault and vault.lower() != ctx.source_name.lower():
        logging.warning('KVSYNC result=ignored cert=%s trigger=%s msg="event is not from the source vault (%s)"', name, etype, vault)
        return
    if etype == "CertificateNearExpiry":
        logging.warning("KVSYNC result=near-expiry cert=%s exp=%s version=%s", name, data.get("EXP"), data.get("Version"))

    try:
        sync_certificate(name, ctx, trigger=etype, event_version=data.get("Version"))
    except Exception as e:  # noqa: BLE001
        # The host retries the message (and finally parks it in the poison queue); the timer sweep is the safety net and is what
        # raises the alert ("failed-transient"), so a one-off race during a rotation does not page anyone.
        report_failure(name, etype, e, result="retrying", level=logging.WARNING, event_version=data.get("Version"))
        raise


if INGEST_MODE == "queue":

    @app.function_name(name="kv_cert_queue")
    @app.queue_trigger(arg_name="msg", queue_name="%SYNC_QUEUE_NAME%", connection="QueueConn")
    def kv_cert_queue(msg: func.QueueMessage) -> None:
        """Storage Queue -> Key Vault certificate event written there by Event Grid (base64 JSON, decoded by the host)."""
        for ev in parse_event_message(msg.get_body()):
            _handle(ev.get("eventType", ""), ev.get("data") or {})

else:

    @app.function_name(name="kv_cert_event")
    @app.event_grid_trigger(arg_name="event")
    def kv_cert_event(event: func.EventGridEvent) -> None:
        """Event Grid -> Key Vault certificate event (NewVersionCreated / NearExpiry) from the SOURCE vault."""
        _handle(event.event_type, event.get_json() or {})


@app.function_name(name="reconcile")
@app.timer_trigger(schedule="%RECONCILE_SCHEDULE%", arg_name="timer", run_on_startup=False)
def reconcile_timer(timer: func.TimerRequest) -> None:
    """Safety net: converge everything opted-in, in case an event was missed."""
    reconcile(_context(), trigger="timer")
