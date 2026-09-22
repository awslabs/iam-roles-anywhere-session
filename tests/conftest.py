"""Shared certificate and key fixtures.

Material is generated per-session in memory and written only under pytest's
``tmp_path_factory``, so no private key ever lands in a predictable location.
"""

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID


def _build_certificate(key, common_name="myfake_org.com"):
    """Self-sign a short-lived certificate for *key*."""
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "France"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "myfake_org"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )


def _private_bytes(key, passphrase=None):
    encryption = (
        serialization.BestAvailableEncryption(passphrase.encode())
        if passphrase
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def _public_bytes(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture(scope="session")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def ec_key():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="session")
def ed25519_key():
    """An unsupported key type, used to assert the rejection path."""
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture(scope="session")
def rsa_cert(rsa_key):
    return _build_certificate(rsa_key)


@pytest.fixture(scope="session")
def ec_cert(ec_key):
    return _build_certificate(ec_key)


@pytest.fixture(scope="session")
def rsa_pem(rsa_key, rsa_cert):
    """(certificate_pem, private_key_pem) for the RSA material."""
    return _public_bytes(rsa_cert), _private_bytes(rsa_key)


@pytest.fixture(scope="session")
def ec_pem(ec_key, ec_cert):
    """(certificate_pem, private_key_pem) for the elliptic curve material."""
    return _public_bytes(ec_cert), _private_bytes(ec_key)


@pytest.fixture(scope="session")
def ed25519_pem(ed25519_key):
    return _private_bytes(ed25519_key)


@pytest.fixture(scope="session")
def encrypted_rsa_pem(rsa_key):
    """(passphrase, encrypted_private_key_pem)."""
    passphrase = "mysecurecomplexpassphrase"
    return passphrase, _private_bytes(rsa_key, passphrase)


@pytest.fixture(scope="session")
def chain_pem(rsa_key):
    """A two-certificate chain in PEM format."""
    first = _build_certificate(rsa_key, "intermediate-a.example")
    second = _build_certificate(rsa_key, "intermediate-b.example")
    return _public_bytes(first) + _public_bytes(second)


@pytest.fixture
def pem_files(tmp_path, rsa_pem):
    """The RSA material written to disk, to exercise the path-based loaders."""
    cert_pem, key_pem = rsa_pem
    cert_path = tmp_path / "certificate.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
    return str(cert_path), str(key_path)


ARNS = {
    "profile_arn": "arn:aws:rolesanywhere:eu-central-1:111122223333:profile/a6294488-77cf-4d4a-8c5c-40b96690bbf0",
    "role_arn": "arn:aws:iam::111122223333:role/IAMRolesAnywhere-01",
    "trust_anchor_arn": "arn:aws:rolesanywhere:eu-central-1:111122223333:trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539",
}
