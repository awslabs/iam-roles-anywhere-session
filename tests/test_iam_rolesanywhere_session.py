from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from iam_rolesanywhere_session import IAMRolesAnywhereSession, IAMRolesAnywhereSigner


def generate_private_key(size: int = 2048):
    return rsa.generate_private_key(
        public_exponent=65537, key_size=size, backend=default_backend()
    )


def generate_certificate(key):
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "France"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "myfake_org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "myfake_org.com"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.utcnow()
            + timedelta(days=1)
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
            # Sign our certificate with our private key
        )
        .sign(key, hashes.SHA256())
    )
    return cert


def write_to_file(b: bytes, filename: str):
    with open(filename, "wb") as f:
        f.write(b)


def get_private_key(key, passphrase=None):
    encryption_algorithm = None
    if passphrase:
        encryption_algorithm = serialization.BestAvailableEncryption(
            passphrase.encode()
        )
    else:
        encryption_algorithm = serialization.NoEncryption()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption_algorithm,
    )


def get_public_cert(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


# Create a private key


key = generate_private_key()

cert = generate_certificate(key)

private_bytes = get_private_key(key)
public_bytes = get_public_cert(cert)
write_to_file(private_bytes, "/tmp/key.pem")
write_to_file(public_bytes, "/tmp/certificate.pem")


def test_load_from_file():
    IAMRolesAnywhereSession(
        profile_arn="arn:aws:rolesanywhere:eu-central-1:************:profile/a6294488-77cf-4d4a-8c5c-40b96690bbf0",
        role_arn="arn:aws:iam::************:role/IAMRolesAnywhere-01",
        trust_anchor_arn="arn:aws:rolesanywhere:eu-central-1::************::trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539",
        certificate="/tmp/certificate.pem",
        private_key="/tmp/key.pem",
        region="eu-central-1",
    )


def test_load_from_bytes():
    IAMRolesAnywhereSession(
        profile_arn="arn:aws:rolesanywhere:eu-central-1:************:profile/a6294488-77cf-4d4a-8c5c-40b96690bbf0",
        role_arn="arn:aws:iam::************:role/IAMRolesAnywhere-01",
        trust_anchor_arn="arn:aws:rolesanywhere:eu-central-1::************::trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539",
        certificate=public_bytes,
        private_key=private_bytes,
        region="eu-central-1",
    )


def test_load_with_passphrase():
    passphrase = "mysecurecomplexpassphrase"
    _private_bytes = get_private_key(key, passphrase)

    IAMRolesAnywhereSession(
        profile_arn="arn:aws:rolesanywhere:eu-central-1:************:profile/a6294488-77cf-4d4a-8c5c-40b96690bbf0",
        role_arn="arn:aws:iam::************:role/IAMRolesAnywhere-01",
        trust_anchor_arn="arn:aws:rolesanywhere:eu-central-1::************::trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539",
        certificate=public_bytes,
        private_key=_private_bytes,
        private_key_passphrase=passphrase,
        region="eu-central-1",
    )


def get_sample_session() -> IAMRolesAnywhereSession:
    return IAMRolesAnywhereSession(
        profile_arn="arn:aws:rolesanywhere:eu-central-1:************:profile/a6294488-77cf-4d4a-8c5c-40b96690bbf0",
        role_arn="arn:aws:iam::************:role/IAMRolesAnywhere-01",
        trust_anchor_arn="arn:aws:rolesanywhere:eu-central-1::************::trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539",
        certificate=public_bytes,
        private_key=private_bytes,
        region="eu-central-1",
    )


def test_create_signer():
    signer = IAMRolesAnywhereSigner(
        certificate=public_bytes,
        private_key=private_bytes,
        certificate_chain=None,
        private_key_passphrase=None,
        region="eu-central-1",
        service_name="rolesanywhere",
    )
    assert isinstance(signer, IAMRolesAnywhereSigner)


def test_algorithm():
    signer = IAMRolesAnywhereSigner(
        certificate=public_bytes,
        private_key=private_bytes,
        certificate_chain=None,
        private_key_passphrase=None,
        region="eu-central-1",
        service_name="rolesanywhere",
    )
    assert signer.algorithm == "AWS4-X509-RSA-SHA256"
