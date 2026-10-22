"""The queue trigger must understand the message that Event Grid really writes: base64-encoded JSON.

This is a regression test for a live finding. With `messageEncoding: none` in host.json every message failed with
JSONDecodeError in 20 ms and ended in the poison queue; only the timer sweep kept the certificates in sync.
Both apps ship their own copy of the parser (they are deployed separately), so the same cases run against both.
"""
import base64
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "sync"))
sys.path.insert(0, str(ROOT / "src" / "renew"))

from kvrenew.core import parse_event_message as parse_renew  # noqa: E402
from kvsync.sync import parse_event_message as parse_sync  # noqa: E402

EVENT = {
    "id": "adb00928-3bff-4c1e-b59a-a5af95de95a1",
    "topic": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-src-xyz",
    "subject": "wildcard-poc",
    "eventType": "Microsoft.KeyVault.CertificateNewVersionCreated",
    "data": {"Id": "https://kv-src-xyz.vault.azure.net/certificates/wildcard-poc/0123", "VaultName": "kv-src-xyz",
             "ObjectType": "Certificate", "ObjectName": "wildcard-poc", "Version": "0123", "NBF": 1, "EXP": 2},
    "dataVersion": "1",
    "metadataVersion": "1",
    "eventTime": "2026-10-21T05:57:36Z",
}


def b64(obj) -> bytes:
    return base64.b64encode(json.dumps(obj).encode()).decode().encode()


class ParseEventMessage(unittest.TestCase):
    def each(self):
        yield "sync", parse_sync
        yield "renew", parse_renew

    def test_base64_json_as_written_by_event_grid(self):
        for who, parse in self.each():
            with self.subTest(who):
                self.assertEqual(parse(b64([EVENT])), [EVENT])

    def test_a_single_event_object_is_accepted(self):
        for who, parse in self.each():
            with self.subTest(who):
                self.assertEqual(parse(b64(EVENT)), [EVENT])

    def test_plain_json_is_accepted_too(self):
        for who, parse in self.each():
            with self.subTest(who):
                self.assertEqual(parse(json.dumps([EVENT]).encode()), [EVENT])
                self.assertEqual(parse(json.dumps(EVENT).encode()), [EVENT])

    def test_surrounding_whitespace_is_ignored(self):
        for who, parse in self.each():
            with self.subTest(who):
                self.assertEqual(parse(b"\n" + b64([EVENT]) + b"\r\n"), [EVENT])

    def test_a_batch_keeps_order(self):
        second = dict(EVENT, id="2", subject="other")
        for who, parse in self.each():
            with self.subTest(who):
                self.assertEqual([e["id"] for e in parse(b64([EVENT, second]))], [EVENT["id"], "2"])

    def test_garbage_raises_so_that_the_host_retries_and_poisons_it(self):
        for who, parse in self.each():
            for bad in (b"not json and not base64 !!", b"1234", b"", b"AAAA"):
                with self.subTest(who=who, bad=bad):
                    with self.assertRaises(ValueError):
                        parse(bad)

    def test_json_that_is_not_an_event_is_dropped_not_crashed_on(self):
        for who, parse in self.each():
            with self.subTest(who):
                self.assertEqual(parse(b64([EVENT, "stray", 3, None])), [EVENT])


if __name__ == "__main__":
    unittest.main()
