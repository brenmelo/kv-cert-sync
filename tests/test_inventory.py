"""The inventory script tells an owner which certificates the factory could replace with one.

Offline: the helpers work on plain rows, so no vault is read.
"""
import importlib.util
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("inventory_vaults", ROOT / "scripts" / "inventory_vaults.py")
inv = importlib.util.module_from_spec(spec)
sys.modules["inventory_vaults"] = inv
spec.loader.exec_module(inv)


def policy(subject, sans=None):
    return types.SimpleNamespace(subject=subject, san_dns_names=sans)


def row(vault, names, **more):
    base = {"vault": vault, "certificate": f"c-{vault}", "enabled": True, "names": names, "tags": "", "error": ""}
    base.update(more)
    return base


class NamesOf(unittest.TestCase):
    def test_sans_are_sorted_and_lower_cased(self):
        self.assertEqual(inv.names_of(policy("CN=a", ["Example.COM", "*.example.com"])), "*.example.com,example.com")

    def test_the_cn_is_used_when_there_are_no_sans(self):
        self.assertEqual(inv.names_of(policy("CN=Shop.Example.com, O=Contoso")), "shop.example.com")

    def test_the_same_names_in_another_order_compare_equal(self):
        self.assertEqual(inv.names_of(policy("CN=a", ["b.example.com", "a.example.com"])),
                         inv.names_of(policy("CN=a", ["a.example.com", "b.example.com"])))

    def test_no_policy_or_no_names_gives_an_empty_string(self):
        self.assertEqual(inv.names_of(None), "")
        self.assertEqual(inv.names_of(policy("O=Contoso")), "")


class DuplicateGroups(unittest.TestCase):
    def test_the_same_names_in_two_vaults_form_a_group(self):
        groups = inv.duplicate_groups([row("kv-a", "*.example.com"), row("kv-b", "*.example.com"), row("kv-c", "other.example.com")])
        self.assertEqual(groups, [{"names": "*.example.com", "vaults": ["kv-a", "kv-b"], "certificates": 2}])

    def test_two_certificates_in_one_vault_are_not_a_duplicate_across_vaults(self):
        self.assertEqual(inv.duplicate_groups([row("kv-a", "x.example.com"), row("kv-a", "x.example.com")]), [])

    def test_replicas_made_by_the_sync_are_not_counted(self):
        groups = inv.duplicate_groups([row("kv-src", "x.example.com", tags="kvsync=all"),
                                       row("kv-dst", "x.example.com", tags="kvsync-origin=kv-src")])
        self.assertEqual(groups, [])

    def test_disabled_certificates_and_unreadable_vaults_are_left_out(self):
        groups = inv.duplicate_groups([row("kv-a", "x.example.com"),
                                       row("kv-b", "x.example.com", enabled=False),
                                       row("kv-c", "", error="403 Forbidden")])
        self.assertEqual(groups, [])

    def test_three_vaults_are_one_group_of_three(self):
        groups = inv.duplicate_groups([row(f"kv-{i}", "*.example.com") for i in "abc"])
        self.assertEqual(groups[0]["vaults"], ["kv-a", "kv-b", "kv-c"])
        self.assertEqual(groups[0]["certificates"], 3)


if __name__ == "__main__":
    unittest.main()
