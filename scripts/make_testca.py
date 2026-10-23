"""Put a private TEST certificate authority into the source vault (proof of concept only).

With CA_PROVIDER=testca the renewal function signs certificate requests with a private CA instead of ordering them from
DigiCert, so the whole chain (request -> sign -> merge -> copy) can be tested without buying a certificate. The CA (its
certificate and its private key) is a secret in the source vault named `ca-testca-bundle`:

    {"ca_cert_pem": "-----BEGIN CERTIFICATE-----...", "ca_key_pem": "-----BEGIN PRIVATE KEY-----..."}

Only the renewal identity can read it (an ABAC condition on the secret name: ca-*). The Terraform proof of concept creates the
secret itself. An ARM / Bicep template cannot generate a key pair, so after the Deploy to Azure proof of concept run this once:

    python scripts/make_testca.py --vault kv-src-<suffix>

Needs `az login` and a role that can write secrets in the source vault (the proof of concept gives the person who deploys Key
Vault Administrator; allow a minute or two for the role assignment to replicate) and:

    pip install azure-identity azure-keyvault-secrets cryptography

The CA is NOT trusted by anything and must never sign a certificate that real clients rely on. The private key is generated here,
sent to the vault and never written to disk or printed.
"""
import argparse
import datetime as dt
import json
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

DEFAULT_SECRET = "ca-testca-bundle"
CA_COMMON_NAME = "KV Cert Sync PoC Test Root CA"
CA_ORGANIZATION = "kv-cert-sync-poc (not a trusted CA)"


def new_ca_bundle(valid_days: int = 365, key_bits: int = 3072, now: dt.datetime | None = None) -> dict:
    """A new self-signed CA as {"ca_cert_pem", "ca_key_pem"}: the format the renewal function reads."""
    if valid_days < 1:
        raise ValueError("valid_days must be at least 1")
    if key_bits < 2048:
        raise ValueError("key_bits must be at least 2048")
    now = now or dt.datetime.now(dt.timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORGANIZATION),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return {
        "ca_cert_pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "ca_key_pem": key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode(),
    }


def vault_url(vault: str) -> str:
    """Accepts a vault name (kv-src-ab12c) or a full address (https://kv-src-ab12c.vault.azure.net)."""
    vault = vault.strip().rstrip("/")
    if not vault:
        raise ValueError("--vault is empty")
    return vault if vault.lower().startswith("https://") else f"https://{vault}.vault.azure.net"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vault", required=True, help="name or address of the SOURCE vault (kv-src-<suffix>)")
    ap.add_argument("--secret-name", default=DEFAULT_SECRET, help=f"default {DEFAULT_SECRET} (must start with ca-)")
    ap.add_argument("--valid-days", type=int, default=365, help="validity of the CA certificate, default 365")
    ap.add_argument("--key-bits", type=int, default=3072, help="RSA key size, default 3072")
    ap.add_argument("--force", action="store_true", help="replace an existing CA (certificates it signed earlier stay valid)")
    ap.add_argument("--ca-cert-out", help="also write the PUBLIC CA certificate to this file (the key is never written)")
    args = ap.parse_args(argv)

    if not args.secret_name.startswith("ca-"):
        ap.error("--secret-name must start with 'ca-': the renewal identity can read only secrets with that prefix")

    from azure.core.exceptions import ResourceNotFoundError
    from azure.identity import AzureCliCredential
    from azure.keyvault.secrets import SecretClient

    client = SecretClient(vault_url=vault_url(args.vault), credential=AzureCliCredential())
    try:
        existing = client.get_secret(args.secret_name)
    except ResourceNotFoundError:
        existing = None
    if existing is not None and not args.force:
        print(f"The secret {args.secret_name!r} already exists in {client.vault_url}; nothing to do (use --force to replace it).")
        return 0

    bundle = new_ca_bundle(args.valid_days, args.key_bits)
    client.set_secret(
        args.secret_name,
        json.dumps(bundle),
        content_type="application/json",
        tags={"purpose": "kv-cert-sync-poc-test-ca"},
    )
    ca = x509.load_pem_x509_certificate(bundle["ca_cert_pem"].encode())
    print(f"Stored the test CA as secret {args.secret_name!r} in {client.vault_url}")
    print(f"  subject  {ca.subject.rfc4514_string()}")
    print(f"  expires  {ca.not_valid_after_utc:%Y-%m-%d}")
    if args.ca_cert_out:
        with open(args.ca_cert_out, "w", encoding="ascii", newline="\n") as fh:
            fh.write(bundle["ca_cert_pem"])
        print(f"  public certificate written to {args.ca_cert_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
