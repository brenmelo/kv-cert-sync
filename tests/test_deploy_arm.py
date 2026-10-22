"""The ARM / Bicep deployment option (deploy/): checks that need no Azure access and no Bicep CLI.

    python -m unittest tests.test_deploy_arm -v

* The function packages that the template downloads are exactly what src/ produces (CI also rebuilds them).
* The committed azuredeploy.json is well-formed, deploys at the right scope, keeps the security settings that the design relies on
  and exposes the same outputs as the Terraform proof of concept, so tests/live/*.py run unchanged against it.
* scripts/make_testca.py writes a CA in the format the renewal function reads, and the function can sign with it.

Whether the template deploys is proved by a real deployment (docs/TEST-REPORT.md), not here. Whether azuredeploy.json is the
compiled form of the Bicep source is checked by CI, which has the Bicep CLI.
"""
import contextlib
import datetime as dt
import importlib.util
import io
import json
import re
import sys
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "renew"))


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


build_packages = load_script("build_packages")
make_testca = load_script("make_testca")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from kvrenew.ca import LocalTestCaClient  # noqa: E402

POC_TEMPLATE = ROOT / "deploy" / "poc" / "azuredeploy.json"

# Azure built-in role definitions the templates assign (the same ids in every tenant and cloud).
BUILT_IN_ROLES = {
    "db79e9a7-68ee-4b58-9aeb-b90e7c24fcba",  # Key Vault Certificate User
    "4633458b-17de-408a-b874-0445c86b69e6",  # Key Vault Secrets User
    "00482a5a-887f-4fb3-b363-3b7fe8e74483",  # Key Vault Administrator
    "a4417e6f-fecd-4de8-b567-7b0420556985",  # Key Vault Certificates Officer
    "b7e6dc6d-f1e8-4753-8033-0f276bb0955b",  # Storage Blob Data Owner
    "974c5e8b-45b9-4653-ba55-5f855dd0fb88",  # Storage Queue Data Contributor
    "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3",  # Storage Table Data Contributor
    "3913510d-42f4-4e42-8a64-420c390055eb",  # Monitoring Metrics Publisher
    "c6a89b2d-59bc-44d0-9896-0f6e12d7b80a",  # Storage Queue Data Message Sender
    "19e7f393-937e-4f77-808e-94535e297925",  # Storage Queue Data Reader
    "76199698-9eea-4c19-bc75-cec21354c6b6",  # Storage Table Data Reader
}


# ----------------------------------------------------------------------------------------------------------------- packages
class Packages(unittest.TestCase):
    def test_committed_packages_are_what_the_source_produces(self):
        for app, src in build_packages.APPS.items():
            path = build_packages.package_path(app)
            self.assertTrue(path.is_file(), f"{path} is missing; run: python scripts/build_packages.py")
            self.assertEqual(path.read_bytes(), build_packages.build(src), f"{app} package is stale; run: python scripts/build_packages.py")

    def test_package_file_name_is_the_one_onedeploy_requires(self):
        for app in build_packages.APPS:
            self.assertEqual(build_packages.package_path(app).name, "released-package.zip")

    def test_build_is_reproducible(self):
        for src in build_packages.APPS.values():
            self.assertEqual(build_packages.build(src), build_packages.build(src))

    def test_entries_are_sorted_stored_and_carry_a_fixed_time_and_mode(self):
        for app in build_packages.APPS:
            with zipfile.ZipFile(build_packages.package_path(app)) as z:
                names = z.namelist()
                self.assertEqual(names, sorted(names))
                for info in z.infolist():
                    self.assertEqual(info.date_time, build_packages.FIXED_TIME, info.filename)
                    self.assertEqual(info.compress_type, zipfile.ZIP_STORED, info.filename)
                    self.assertEqual(info.external_attr, build_packages.FIXED_MODE, info.filename)

    def test_a_package_holds_one_function_app_and_nothing_local(self):
        for app in build_packages.APPS:
            with zipfile.ZipFile(build_packages.package_path(app)) as z:
                names = set(z.namelist())
                for required in ("function_app.py", "host.json", "requirements.txt"):
                    self.assertIn(required, names, f"{app} package lacks {required}")
                for name in names:
                    parts = set(Path(name).parts)
                    self.assertFalse(parts & build_packages.SKIP_DIRS, name)
                    self.assertNotIn(Path(name).name, build_packages.SKIP_FILES, name)
                    self.assertFalse(name.endswith((".pyc", ".pyo")), name)
                    self.assertFalse(name.startswith("/") or ".." in Path(name).parts, name)

    def test_text_files_use_unix_line_endings(self):
        for app in build_packages.APPS:
            with zipfile.ZipFile(build_packages.package_path(app)) as z:
                for info in z.infolist():
                    if Path(info.filename).suffix in build_packages.TEXT_SUFFIXES:
                        self.assertNotIn(b"\r\n", z.read(info), info.filename)

    def test_the_two_apps_are_not_mixed_up(self):
        with zipfile.ZipFile(build_packages.package_path("sync")) as z:
            self.assertTrue(any(n.startswith("kvsync/") for n in z.namelist()))
            self.assertFalse(any(n.startswith("kvrenew/") for n in z.namelist()))
        with zipfile.ZipFile(build_packages.package_path("renew")) as z:
            self.assertTrue(any(n.startswith("kvrenew/") for n in z.namelist()))
            self.assertFalse(any(n.startswith("kvsync/") for n in z.namelist()))


# ----------------------------------------------------------------------------------------------------------------- template
def iter_resources(template):
    """Every resource of an ARM template, including those inside inline nested deployments."""
    resources = template.get("resources", [])
    if isinstance(resources, dict):  # languageVersion 2.0 form
        resources = list(resources.values())
    for r in resources:
        yield r
        inner = r.get("properties", {}).get("template")
        if r.get("type") == "Microsoft.Resources/deployments" and isinstance(inner, dict):
            yield from iter_resources(inner)


class Template(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = json.loads(POC_TEMPLATE.read_text(encoding="utf-8"))
        cls.resources = list(iter_resources(cls.template))

    def of_type(self, resource_type):
        return [r for r in self.resources if r.get("type") == resource_type]

    def test_it_deploys_at_subscription_scope(self):
        self.assertTrue(self.template["$schema"].endswith("subscriptionDeploymentTemplate.json#"), self.template["$schema"])

    def test_the_bicep_source_is_next_to_it_and_every_module_exists(self):
        main = POC_TEMPLATE.with_name("main.bicep")
        self.assertTrue(main.is_file())
        for bicep in (ROOT / "deploy").rglob("*.bicep"):
            for ref in re.findall(r"^module\s+\w+\s+'([^']+)'", bicep.read_text(encoding="utf-8"), flags=re.M):
                self.assertTrue((bicep.parent / ref).is_file(), f"{bicep.name} references {ref}")

    def test_every_parameter_is_documented_and_none_is_a_secret(self):
        for name, p in self.template["parameters"].items():
            self.assertTrue(p.get("metadata", {}).get("description"), f"parameter {name} has no description")
            self.assertNotIn(p["type"].lower(), ("securestring", "secureobject"), name)

    def test_default_package_location_is_public_and_generic(self):
        base = self.template["parameters"]["packageBaseUri"]["defaultValue"]
        self.assertTrue(base.startswith("https://raw.githubusercontent.com/"), base)
        self.assertTrue(base.endswith("/deploy/packages"), base)

    def test_outputs_are_the_ones_the_terraform_proof_of_concept_has(self):
        tf = (ROOT / "terraform" / "poc" / "outputs.tf").read_text(encoding="utf-8")
        wanted = set(re.findall(r'^output "(\w+)"', tf, flags=re.M)) - {"app_gateway"}  # the Application Gateway test is Terraform-only
        self.assertEqual(set(self.template["outputs"]), wanted)

    def test_there_are_no_vault_access_policies_only_rbac(self):
        vaults = self.of_type("Microsoft.KeyVault/vaults")
        self.assertGreaterEqual(len(vaults), 3)  # source + two destinations
        for v in vaults:
            props = v["properties"]
            self.assertIs(props["enableRbacAuthorization"], True)
            self.assertNotIn("accessPolicies", props)

    def test_storage_accounts_have_no_account_key(self):
        accounts = self.of_type("Microsoft.Storage/storageAccounts")
        self.assertEqual(len(accounts), 2)  # one per function app
        for a in accounts:
            props = a["properties"]
            self.assertIs(props["allowSharedKeyAccess"], False)
            self.assertIs(props["allowBlobPublicAccess"], False)
            self.assertEqual(props["minimumTlsVersion"], "TLS1_2")

    def test_function_apps_use_a_user_assigned_identity_https_and_no_publishing_password(self):
        sites = self.of_type("Microsoft.Web/sites")
        self.assertEqual(len(sites), 2)
        for s in sites:
            self.assertIs(s["properties"]["httpsOnly"], True)
            self.assertEqual(s["identity"]["type"], "UserAssigned")
            self.assertEqual(s["properties"]["siteConfig"]["ftpsState"], "Disabled")
        policies = self.of_type("Microsoft.Web/sites/basicPublishingCredentialsPolicies")
        self.assertEqual(len(policies), 4)  # ftp and scm for each app
        for p in policies:
            self.assertIs(p["properties"]["allow"], False)

    def test_code_is_deployed_from_a_package_with_a_remote_build(self):
        deploys = self.of_type("Microsoft.Web/sites/extensions")
        self.assertEqual(len(deploys), 2)
        for d in deploys:
            self.assertIn("onedeploy", d["name"])
            self.assertIs(d["properties"]["remoteBuild"], True)
        text = POC_TEMPLATE.read_text(encoding="utf-8")  # each app downloads its own package, named as OneDeploy requires
        self.assertIn("/sync/released-package.zip", text)
        self.assertIn("/renew/released-package.zip", text)

    def test_events_are_delivered_with_managed_identity_to_a_queue(self):
        subs = self.of_type("Microsoft.EventGrid/systemTopics/eventSubscriptions")
        self.assertEqual(len(subs), 2)
        for s in subs:
            delivery = s["properties"]["deliveryWithResourceIdentity"]
            self.assertEqual(delivery["identity"]["type"], "SystemAssigned")
            self.assertEqual(delivery["destination"]["endpointType"], "StorageQueue")

    def test_the_custom_roles_are_the_least_privilege_ones_of_terraform(self):
        roles = {re.search(r"KV Certificate (\w+)", r["properties"]["roleName"]).group(1): r["properties"] for r in self.of_type("Microsoft.Authorization/roleDefinitions")}
        self.assertEqual(set(roles), {"Importer", "Issuer"})
        data_actions = lambda p: sorted(p["permissions"][0]["dataActions"])  # noqa: E731
        self.assertEqual(data_actions(roles["Importer"]), [
            "Microsoft.KeyVault/vaults/certificates/import/action", "Microsoft.KeyVault/vaults/certificates/read"])
        self.assertEqual(data_actions(roles["Issuer"]), [
            "Microsoft.KeyVault/vaults/certificates/create/action", "Microsoft.KeyVault/vaults/certificates/read",
            "Microsoft.KeyVault/vaults/certificates/update/action"])
        for p in roles.values():
            self.assertEqual(p["permissions"][0]["actions"], [])

    def test_alert_rules_search_for_the_log_lines_terraform_alerts_on(self):
        tf = (ROOT / "terraform" / "modules" / "hub" / "alerts.tf").read_text(encoding="utf-8")
        tf_phrases = set(re.findall(r'(?:KVSYNC|KVRENEW) result=[\w-]+', tf))
        tf_phrases |= {"KVSYNC result=reconcile-complete", "KVRENEW result=reconcile-complete"}  # Terraform builds these from a per-app prefix
        rules = self.of_type("Microsoft.Insights/scheduledQueryRules")
        self.assertEqual(len(rules), 4)
        arm_phrases = set()
        for r in rules:
            for criterion in r["properties"]["criteria"]["allOf"]:
                arm_phrases |= set(re.findall(r'(?:KVSYNC|KVRENEW) result=[\w-]+', criterion["query"]))
            self.assertIs(r["properties"]["autoMitigate"], True)
        self.assertEqual(arm_phrases, tf_phrases)

    def test_no_tenant_subscription_or_person_is_baked_in(self):
        text = POC_TEMPLATE.read_text(encoding="utf-8")
        found = set(re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text, flags=re.I))
        self.assertEqual(found - BUILT_IN_ROLES, set(), "only Azure built-in role ids may appear as literals")
        self.assertNotRegex(text, r"@[\w-]+\.(com|org|net)\b")  # no e-mail address


# ----------------------------------------------------------------------------------------------------------------- test CA
class TestCa(unittest.TestCase):
    def test_the_bundle_is_a_ca_whose_key_matches_its_certificate(self):
        now = dt.datetime(2026, 11, 1, 12, 0, tzinfo=dt.timezone.utc)
        bundle = make_testca.new_ca_bundle(valid_days=2, key_bits=2048, now=now)
        self.assertEqual(set(bundle), {"ca_cert_pem", "ca_key_pem"})
        cert = x509.load_pem_x509_certificate(bundle["ca_cert_pem"].encode())
        key = serialization.load_pem_private_key(bundle["ca_key_pem"].encode(), password=None)
        self.assertEqual(cert.public_key().public_numbers(), key.public_key().public_numbers())
        self.assertEqual(cert.subject, cert.issuer)
        self.assertTrue(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(usage.key_cert_sign and not usage.digital_signature)
        self.assertEqual(cert.not_valid_after_utc, now + dt.timedelta(days=2))
        self.assertIn("not a trusted CA", cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value)

    def test_bundle_is_json_serializable_and_never_holds_an_encrypted_key(self):
        bundle = make_testca.new_ca_bundle(1, 2048)
        self.assertEqual(json.loads(json.dumps(bundle)), bundle)
        self.assertTrue(bundle["ca_key_pem"].startswith("-----BEGIN PRIVATE KEY-----"))  # the function reads it without a passphrase

    def test_the_renewal_function_signs_a_request_with_it(self):
        bundle = make_testca.new_ca_bundle(1, 2048)
        leaf_key = rsa.generate_private_key(65537, 2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "*.example.test")]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("*.example.test"), x509.DNSName("example.test")]), critical=False)
            .sign(leaf_key, hashes.SHA256())
        )
        ca = LocalTestCaClient(lambda: bundle, days=30)
        order = ca.submit(csr.public_bytes(serialization.Encoding.DER), None)
        chain = ca.fetch_chain(order, csr.public_bytes(serialization.Encoding.DER))
        leaf, root = (x509.load_der_x509_certificate(c) for c in chain)
        root.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, padding.PKCS1v15(), leaf.signature_hash_algorithm)
        self.assertEqual(root.subject, leaf.issuer)

    def test_vault_url(self):
        self.assertEqual(make_testca.vault_url("kv-src-ab12c"), "https://kv-src-ab12c.vault.azure.net")
        self.assertEqual(make_testca.vault_url(" https://kv-src-ab12c.vault.usgovcloudapi.net/ "), "https://kv-src-ab12c.vault.usgovcloudapi.net")
        with self.assertRaises(ValueError):
            make_testca.vault_url("  ")

    def test_a_secret_name_the_renewal_identity_could_not_read_is_refused_before_any_network_call(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            make_testca.main(["--vault", "kv-src-ab12c", "--secret-name", "testca"])
        self.assertEqual(raised.exception.code, 2)

    def test_a_weak_key_or_a_zero_validity_is_refused(self):
        with self.assertRaises(ValueError):
            make_testca.new_ca_bundle(valid_days=0)
        with self.assertRaises(ValueError):
            make_testca.new_ca_bundle(key_bits=1024)


if __name__ == "__main__":
    unittest.main()
