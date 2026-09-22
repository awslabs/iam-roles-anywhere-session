#!/usr/bin/env python3
"""Generate a throwaway CA and client certificate for IAM Roles Anywhere.

IAM Roles Anywhere trust anchors accept a `CERTIFICATE_BUNDLE`, so a self-signed
CA is enough to exercise the full signing path. AWS Private CA is not required
and bills per CA per month.

The key material produced here is for testing only. It is written to this
directory, which .gitignore excludes.

    python3 make_certs.py --key-type rsa
    python3 make_certs.py --key-type ec --out-dir ./ec
"""

import argparse
import pathlib
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def generate_key(key_type):
    if key_type == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return ec.generate_private_key(ec.SECP256R1())


def name(common_name):
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "iam-ra-smoketest"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def build_ca(key, days):
    """Self-sign a CA certificate. This PEM becomes the trust anchor bundle."""
    subject = name("iam-ra-smoketest-ca")
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )


def build_client(client_key, ca_key, ca_cert, days):
    """Issue an end-entity certificate for the workload.

    IAM Roles Anywhere requires `digitalSignature` key usage and the
    `clientAuth` extended key usage on the certificate it authenticates.
    """
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name("iam-ra-smoketest-client"))
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )


def write_key(path, key):
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


def write_cert(path, cert):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--key-type",
        choices=["rsa", "ec"],
        default="rsa",
        help="Key algorithm. Use both in turn to cover each signing path.",
    )
    parser.add_argument("--days", type=int, default=7, help="Validity in days.")
    parser.add_argument(
        "--out-dir",
        type=pathlib.Path,
        default=pathlib.Path(__file__).parent,
        help="Where to write the PEM files.",
    )
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    ca_key = generate_key(args.key_type)
    ca_cert = build_ca(ca_key, args.days)
    client_key = generate_key(args.key_type)
    client_cert = build_client(client_key, ca_key, ca_cert, args.days)

    paths = {
        "ca.key": (write_key, ca_key),
        "ca.pem": (write_cert, ca_cert),
        "client.key": (write_key, client_key),
        "client.pem": (write_cert, client_cert),
    }
    for filename, (writer, obj) in paths.items():
        writer(args.out_dir / filename, obj)

    print(f"Wrote {args.key_type.upper()} test material to {args.out_dir}:")
    print("  ca.pem      -> trust anchor bundle (terraform reads this)")
    print("  client.pem  -> certificate for the session")
    print("  client.key  -> private key for the session")
    print("  ca.key      -> only needed to issue more client certificates")
    print(f"\nValid for {args.days} days. Do not reuse outside this test.")


if __name__ == "__main__":
    main()
