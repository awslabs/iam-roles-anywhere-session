"""Behavioural tests for session construction and credential retrieval."""

import json
import logging
from datetime import datetime, timedelta, timezone

import pytest
from botocore.awsrequest import AWSRequest

import iam_rolesanywhere_session
from conftest import ARNS
from iam_rolesanywhere_session import (
    MAX_SESSION_DURATION,
    MIN_SESSION_DURATION,
    CredentialsRetrievalError,
    IAMRolesAnywhereSession,
    IAMRolesAnywhereSigner,
    InvalidSessionDurationError,
    UnsupportedFipsEndpointError,
    UnsupportedPrivateKeyError,
)

ACCESS_KEY = "ASIAIOSFODNN7EXAMPLE"
SECRET_KEY = "wJalrXUtnFEMIsecretEXAMPLEKEY"
SESSION_TOKEN = "IQoJb3JpZ2luX2VjEXAMPLESESSIONTOKEN"


class StubResponse:
    """Minimal stand-in for ``AWSResponse``."""

    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


class StubHTTPSession:
    """Captures the request instead of putting it on the wire."""

    def __init__(self, response):
        self._response = response
        self.sent = []

    def send(self, request):
        self.sent.append(request)
        return self._response


def credential_payload(expiration=None):
    if expiration is None:
        expiration = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    return json.dumps(
        {
            "credentialSet": [
                {
                    "credentials": {
                        "accessKeyId": ACCESS_KEY,
                        "secretAccessKey": SECRET_KEY,
                        "sessionToken": SESSION_TOKEN,
                        "expiration": expiration,
                    }
                }
            ]
        }
    )


def make_session(rsa_pem, **overrides):
    cert_pem, key_pem = rsa_pem
    kwargs = dict(
        ARNS,
        certificate=cert_pem,
        private_key=key_pem,
        region="eu-central-1",
    )
    kwargs.update(overrides)
    return IAMRolesAnywhereSession(**kwargs)


def fetch_credentials(session):
    """Invoke the name-mangled private credential fetch."""
    return session._IAMRolesAnywhereSession__get_credentials()


def attach_stub(session, status_code, text):
    stub = StubHTTPSession(StubResponse(status_code, text))
    session._session = stub
    return stub


# --------------------------------------------------------------------------
# Construction
# --------------------------------------------------------------------------


def test_load_from_file(pem_files):
    cert_path, key_path = pem_files
    session = IAMRolesAnywhereSession(
        **ARNS, certificate=cert_path, private_key=key_path, region="eu-central-1"
    )
    assert session._request_signer.private_key_type == "RSA"


def test_load_from_bytes(rsa_pem):
    assert make_session(rsa_pem)._request_signer.private_key_type == "RSA"


def test_load_with_passphrase(rsa_pem, encrypted_rsa_pem):
    cert_pem, _ = rsa_pem
    passphrase, key_pem = encrypted_rsa_pem
    session = IAMRolesAnywhereSession(
        **ARNS,
        certificate=cert_pem,
        private_key=key_pem,
        private_key_passphrase=passphrase,
        region="eu-central-1",
    )
    assert session._request_signer.private_key_type == "RSA"


def test_unsupported_private_key_type(rsa_pem, ed25519_pem):
    cert_pem, _ = rsa_pem
    with pytest.raises(UnsupportedPrivateKeyError):
        IAMRolesAnywhereSession(
            **ARNS, certificate=cert_pem, private_key=ed25519_pem, region="eu-central-1"
        )


def test_unsupported_private_key_is_still_a_type_error(rsa_pem, ed25519_pem):
    """v2 raised a bare TypeError here; existing handlers must keep working."""
    cert_pem, _ = rsa_pem
    with pytest.raises(TypeError):
        IAMRolesAnywhereSession(
            **ARNS, certificate=cert_pem, private_key=ed25519_pem, region="eu-central-1"
        )


# --------------------------------------------------------------------------
# Signing
# --------------------------------------------------------------------------


def build_signer(cert_pem, key_pem, **kwargs):
    return IAMRolesAnywhereSigner(
        certificate=cert_pem,
        private_key=key_pem,
        region=kwargs.pop("region", "eu-central-1"),
        service_name=kwargs.pop("service_name", "rolesanywhere"),
        **kwargs,
    )


def sign(signer, url="https://rolesanywhere.eu-central-1.amazonaws.com/sessions"):
    """Sign a request, returning it along with the exact StringToSign used."""
    request = AWSRequest(method="POST", url=url, data="{}")
    captured = {}
    original = signer.signature

    def spy(string_to_sign, _=None):
        captured["string_to_sign"] = string_to_sign
        return original(string_to_sign)

    signer.signature = spy
    signer.add_auth(request)
    return request, captured["string_to_sign"]


@pytest.mark.parametrize("material,expected", [("rsa_pem", "RSA"), ("ec_pem", "ECDSA")])
def test_algorithm_matches_key_type(request, material, expected):
    cert_pem, key_pem = request.getfixturevalue(material)
    signer = build_signer(cert_pem, key_pem)
    assert signer.private_key_type == expected
    assert signer.algorithm == f"AWS4-X509-{expected}-SHA256"


@pytest.mark.parametrize("material", ["rsa_pem", "ec_pem"])
def test_signature_verifies_against_certificate(request, material):
    """The emitted signature must validate under the certificate's public key.

    This is the test that would have caught a malformed canonical request or a
    mismatched signing algorithm.
    """
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDSA,
        EllipticCurvePublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
    from cryptography.hazmat.primitives.hashes import SHA256

    cert_pem, key_pem = request.getfixturevalue(material)
    signer = build_signer(cert_pem, key_pem)
    signed, string_to_sign = sign(signer)

    signature = bytes.fromhex(
        signed.headers["Authorization"].split("Signature=")[1].strip()
    )
    public_key = signer.certificate.public_key()
    if isinstance(public_key, EllipticCurvePublicKey):
        public_key.verify(signature, string_to_sign.encode("utf-8"), ECDSA(SHA256()))
    else:
        public_key.verify(
            signature, string_to_sign.encode("utf-8"), PKCS1v15(), SHA256()
        )


def test_authorization_header_structure(rsa_pem):
    cert_pem, key_pem = rsa_pem
    signer = build_signer(cert_pem, key_pem)
    signed, _ = sign(signer)

    algorithm, _, remainder = signed.headers["Authorization"].partition(" ")
    credential, signed_headers, signature = remainder.split(", ")
    serial, date, region, service, terminator = credential.removeprefix(
        "Credential="
    ).split("/")

    assert algorithm == "AWS4-X509-RSA-SHA256"
    assert serial == str(signer.certificate.serial_number)
    assert date == signed.context["timestamp"][0:8]
    assert (region, service, terminator) == (
        "eu-central-1",
        "rolesanywhere",
        "aws4_request",
    )
    assert signed_headers.startswith("SignedHeaders=")
    assert "host" in signed_headers
    assert signature.startswith("Signature=")


def test_string_to_sign_layout(rsa_pem):
    cert_pem, key_pem = rsa_pem
    signer = build_signer(cert_pem, key_pem)
    signed, string_to_sign = sign(signer)

    algorithm, amz_date, scope, payload_hash = string_to_sign.split("\n")
    assert algorithm == "AWS4-X509-RSA-SHA256"
    assert amz_date == signed.context["timestamp"]
    assert scope == f"{amz_date[0:8]}/eu-central-1/rolesanywhere/aws4_request"
    assert len(payload_hash) == 64


def test_certificate_header_is_base64_der(rsa_pem):
    import base64

    from cryptography.hazmat.primitives import serialization

    cert_pem, key_pem = rsa_pem
    signer = build_signer(cert_pem, key_pem)
    signed, _ = sign(signer)

    expected = base64.b64encode(
        signer.certificate.public_bytes(serialization.Encoding.DER)
    ).decode()
    assert signed.headers["X-Amz-X509"] == expected
    assert "X-Amz-X509-Chain" not in signed.headers


def test_certificate_chain_header(rsa_pem, chain_pem):
    cert_pem, key_pem = rsa_pem
    signer = build_signer(cert_pem, key_pem, certificate_chain=chain_pem)
    signed, _ = sign(signer)

    chain_header = signed.headers["X-Amz-X509-Chain"]
    assert len(chain_header.split(",")) == 2


def test_content_type_header(rsa_pem):
    cert_pem, key_pem = rsa_pem
    signed, _ = sign(build_signer(cert_pem, key_pem))
    assert signed.headers["Content-Type"] == "application/x-amz-json-1.0"


# --------------------------------------------------------------------------
# Host header: regression tests for signing a host other than the one called
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,expected_host",
    [
        (
            "https://rolesanywhere.eu-central-1.amazonaws.com/sessions",
            "rolesanywhere.eu-central-1.amazonaws.com",
        ),
        (
            "https://rolesanywhere-fips.us-east-1.amazonaws.com/sessions",
            "rolesanywhere-fips.us-east-1.amazonaws.com",
        ),
        (
            "https://rolesanywhere.cn-north-1.amazonaws.com.cn/sessions",
            "rolesanywhere.cn-north-1.amazonaws.com.cn",
        ),
        (
            "https://vpce-0123-abcd.rolesanywhere.eu-west-1.vpce.amazonaws.com/sessions",
            "vpce-0123-abcd.rolesanywhere.eu-west-1.vpce.amazonaws.com",
        ),
    ],
)
def test_signed_host_matches_request_url(rsa_pem, url, expected_host):
    cert_pem, key_pem = rsa_pem
    signed, _ = sign(build_signer(cert_pem, key_pem), url=url)
    assert signed.headers["Host"] == expected_host


def test_signing_twice_does_not_duplicate_headers(rsa_pem):
    """``AWSRequest.headers`` appends on assignment, so replacement must be explicit."""
    cert_pem, key_pem = rsa_pem
    signer = build_signer(cert_pem, key_pem)
    request = AWSRequest(
        method="POST",
        url="https://rolesanywhere.eu-central-1.amazonaws.com/sessions",
        data="{}",
    )
    signer.add_auth(request)
    signer.add_auth(request)

    for header in ("Host", "Content-Type", "X-Amz-X509", "Authorization"):
        assert len(request.headers.get_all(header)) == 1, f"{header} was duplicated"


# --------------------------------------------------------------------------
# Endpoint resolution
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "region,expected",
    [
        ("us-east-1", "rolesanywhere.us-east-1.amazonaws.com"),
        ("eu-central-1", "rolesanywhere.eu-central-1.amazonaws.com"),
        ("cn-north-1", "rolesanywhere.cn-north-1.amazonaws.com.cn"),
        ("us-gov-west-1", "rolesanywhere.us-gov-west-1.amazonaws.com"),
    ],
)
def test_default_endpoint_is_partition_aware(rsa_pem, region, expected):
    assert make_session(rsa_pem, region=region).endpoint == expected


def test_fips_endpoint_is_resolved(rsa_pem):
    session = make_session(rsa_pem, region="us-east-1", use_fips_endpoint=True)
    assert session.endpoint == "rolesanywhere-fips.us-east-1.amazonaws.com"


def test_fips_endpoint_is_the_host_that_gets_signed(rsa_pem):
    session = make_session(rsa_pem, region="us-east-1", use_fips_endpoint=True)
    stub = attach_stub(session, 200, credential_payload())
    fetch_credentials(session)
    assert stub.sent[0].headers["Host"] == "rolesanywhere-fips.us-east-1.amazonaws.com"


@pytest.mark.parametrize("region", ["eu-central-1", "ap-southeast-2", "sa-east-1"])
def test_fips_in_a_region_without_a_fips_endpoint_is_rejected(rsa_pem, region):
    """botocore would synthesise a hostname that does not resolve in DNS."""
    with pytest.raises(UnsupportedFipsEndpointError) as excinfo:
        make_session(rsa_pem, region=region, use_fips_endpoint=True)

    assert excinfo.value.region_name == region
    assert "us-east-1" in excinfo.value.supported
    assert region in str(excinfo.value)


def test_unsupported_fips_is_still_a_value_error(rsa_pem):
    with pytest.raises(ValueError):
        make_session(rsa_pem, region="eu-central-1", use_fips_endpoint=True)


@pytest.mark.parametrize(
    "region", ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "us-gov-west-1"]
)
def test_fips_is_accepted_where_the_endpoint_exists(rsa_pem, region):
    session = make_session(rsa_pem, region=region, use_fips_endpoint=True)
    assert session.endpoint == f"rolesanywhere-fips.{region}.amazonaws.com"


def test_explicit_endpoint_is_respected(rsa_pem):
    session = make_session(
        rsa_pem, endpoint="rolesanywhere-fips.us-east-1.amazonaws.com"
    )
    assert session.endpoint == "rolesanywhere-fips.us-east-1.amazonaws.com"


def test_explicit_endpoint_is_the_host_that_gets_signed(rsa_pem):
    """End-to-end: a custom endpoint must reach the wire *and* the signature."""
    session = make_session(
        rsa_pem, endpoint="rolesanywhere-fips.us-east-1.amazonaws.com"
    )
    stub = attach_stub(session, 200, credential_payload())
    fetch_credentials(session)

    sent = stub.sent[0]
    assert sent.url == "https://rolesanywhere-fips.us-east-1.amazonaws.com/sessions"
    assert sent.headers["Host"] == "rolesanywhere-fips.us-east-1.amazonaws.com"


# --------------------------------------------------------------------------
# Session duration
# --------------------------------------------------------------------------


@pytest.mark.parametrize("duration", [MIN_SESSION_DURATION, 3600, MAX_SESSION_DURATION])
def test_valid_session_durations(rsa_pem, duration):
    assert make_session(rsa_pem, session_duration=duration).session_duration == duration


@pytest.mark.parametrize("duration", [0, 899, MAX_SESSION_DURATION + 1, 86400])
def test_invalid_session_durations(rsa_pem, duration):
    with pytest.raises(InvalidSessionDurationError):
        make_session(rsa_pem, session_duration=duration)


def test_invalid_duration_is_still_a_value_error(rsa_pem):
    with pytest.raises(ValueError):
        make_session(rsa_pem, session_duration=1)


# --------------------------------------------------------------------------
# Request body
# --------------------------------------------------------------------------


def test_request_body_defaults(rsa_pem):
    body = make_session(rsa_pem)._build_session_request_body()
    assert body == {
        "durationSeconds": 3600,
        "profileArn": ARNS["profile_arn"],
        "roleArn": ARNS["role_arn"],
        "trustAnchorArn": ARNS["trust_anchor_arn"],
    }


def test_optional_members_are_omitted_when_unset(rsa_pem):
    body = make_session(rsa_pem)._build_session_request_body()
    assert "roleSessionName" not in body
    assert "instanceProperties" not in body


def test_role_session_name_is_sent(rsa_pem):
    body = make_session(
        rsa_pem, role_session_name="my-workload"
    )._build_session_request_body()
    assert body["roleSessionName"] == "my-workload"


def test_instance_properties_are_sent(rsa_pem):
    properties = {"workload": "batch", "tier": "prod"}
    body = make_session(
        rsa_pem, instance_properties=properties
    )._build_session_request_body()
    assert body["instanceProperties"] == properties


def test_body_reaches_the_wire(rsa_pem):
    session = make_session(rsa_pem, role_session_name="my-workload")
    stub = attach_stub(session, 200, credential_payload())
    fetch_credentials(session)
    assert json.loads(stub.sent[0].body)["roleSessionName"] == "my-workload"


# --------------------------------------------------------------------------
# Credential retrieval
# --------------------------------------------------------------------------


def test_successful_retrieval_maps_fields(rsa_pem):
    session = make_session(rsa_pem)
    attach_stub(session, 200, credential_payload(expiration="2030-01-01T00:00:00Z"))

    assert fetch_credentials(session) == {
        "access_key": ACCESS_KEY,
        "secret_key": SECRET_KEY,
        "token": SESSION_TOKEN,
        "expiry_time": "2030-01-01T00:00:00Z",
    }


def test_refreshable_credentials_end_to_end(rsa_pem):
    """Exercise the documented public path, not just the private fetch."""
    session = make_session(rsa_pem)
    attach_stub(session, 200, credential_payload())

    frozen = session.get_refreshable_credentials().get_frozen_credentials()
    assert frozen.access_key == ACCESS_KEY
    assert frozen.secret_key == SECRET_KEY
    assert frozen.token == SESSION_TOKEN


def test_get_session_returns_configured_boto3_session(rsa_pem):
    import boto3

    session = make_session(rsa_pem, proxies={"https": "http://proxy.example:3128"})
    attach_stub(session, 200, credential_payload())

    boto_session = session.get_session()
    assert isinstance(boto_session, boto3.session.Session)
    assert boto_session.region_name == "eu-central-1"

    # Proxies must reach the clients the session hands out, not merely be
    # stashed on the session where nothing reads them.
    client = boto_session.client("s3", aws_access_key_id="a", aws_secret_access_key="b")
    assert client.meta.config.proxies == {"https": "http://proxy.example:3128"}


def client_verify(session, **client_kwargs):
    """The TLS verification setting a client built from *session* actually uses."""
    client = session.client(
        "s3", aws_access_key_id="a", aws_secret_access_key="b", **client_kwargs
    )
    return client._endpoint.http_session._verify


def test_ca_bundle_path_propagates_to_clients(rsa_pem, tmp_path):
    bundle = tmp_path / "corp-ca.pem"
    bundle.write_bytes(b"")
    session = make_session(rsa_pem, verify=str(bundle))
    attach_stub(session, 200, credential_payload())

    boto_session = session.get_session()
    assert boto_session._session.get_config_variable("ca_bundle") == str(bundle)
    assert client_verify(boto_session) == str(bundle)


def test_verify_false_propagates_to_clients(rsa_pem):
    session = make_session(rsa_pem, verify=False)
    attach_stub(session, 200, credential_payload())
    assert client_verify(session.get_session()) is False


def test_verify_true_leaves_clients_at_the_default(rsa_pem):
    session = make_session(rsa_pem, verify=True)
    attach_stub(session, 200, credential_payload())
    assert client_verify(session.get_session()) is True


def test_explicit_client_verify_overrides_the_session_default(rsa_pem):
    session = make_session(rsa_pem, verify=False)
    attach_stub(session, 200, credential_payload())
    assert client_verify(session.get_session(), verify=True) is True


def test_disabling_verification_is_warned_about(rsa_pem, caplog):
    with caplog.at_level(logging.WARNING, logger="iam_rolesanywhere_session"):
        make_session(rsa_pem, verify=False)
    assert "verification is disabled" in caplog.text


def test_session_without_proxies_keeps_default_client_config(rsa_pem):
    session = make_session(rsa_pem)
    attach_stub(session, 200, credential_payload())
    assert session.get_session()._session.get_default_client_config() is None


def test_get_session_kwargs_override_config(rsa_pem):
    session = make_session(rsa_pem)
    attach_stub(session, 200, credential_payload())
    assert session.get_session(region="us-west-2").region_name == "us-west-2"


def test_error_status_with_json_message(rsa_pem):
    session = make_session(rsa_pem)
    attach_stub(session, 403, json.dumps({"message": "Profile is disabled"}))

    with pytest.raises(CredentialsRetrievalError) as excinfo:
        fetch_credentials(session)

    assert excinfo.value.status_code == 403
    assert excinfo.value.message == "Profile is disabled"
    assert "403" in str(excinfo.value)


def test_error_status_with_non_json_body(rsa_pem):
    """Regression for PR #20: a proxy's HTML error must not become a JSON error."""
    session = make_session(rsa_pem)
    attach_stub(session, 502, "<html><body>502 Bad Gateway</body></html>")

    with pytest.raises(CredentialsRetrievalError) as excinfo:
        fetch_credentials(session)

    assert excinfo.value.status_code == 502
    assert "502 Bad Gateway" in excinfo.value.message


def test_error_status_with_empty_body(rsa_pem):
    session = make_session(rsa_pem)
    attach_stub(session, 500, "")

    with pytest.raises(CredentialsRetrievalError) as excinfo:
        fetch_credentials(session)
    assert excinfo.value.status_code == 500


def test_error_status_with_alternate_message_key(rsa_pem):
    session = make_session(rsa_pem)
    attach_stub(session, 400, json.dumps({"__type": "ValidationException"}))

    with pytest.raises(CredentialsRetrievalError) as excinfo:
        fetch_credentials(session)
    assert excinfo.value.message == "ValidationException"


def test_success_status_with_unparseable_body(rsa_pem):
    session = make_session(rsa_pem)
    attach_stub(session, 200, "not json at all")

    with pytest.raises(CredentialsRetrievalError, match="not valid JSON"):
        fetch_credentials(session)


@pytest.mark.parametrize(
    "payload",
    [
        json.dumps({}),
        json.dumps({"credentialSet": []}),
        json.dumps({"credentialSet": [{}]}),
        json.dumps({"credentialSet": "unexpected"}),
    ],
)
def test_success_status_without_credential_set(rsa_pem, payload):
    session = make_session(rsa_pem)
    attach_stub(session, 200, payload)

    with pytest.raises(CredentialsRetrievalError, match="credential set"):
        fetch_credentials(session)


def test_credentials_are_never_logged(rsa_pem, caplog):
    """Security regression: the response body carries live credentials."""
    session = make_session(rsa_pem)
    attach_stub(session, 200, credential_payload())

    with caplog.at_level(logging.DEBUG, logger="iam_rolesanywhere_session"):
        fetch_credentials(session)

    assert SECRET_KEY not in caplog.text
    assert SESSION_TOKEN not in caplog.text
    assert ACCESS_KEY not in caplog.text


def test_error_message_is_logged(rsa_pem, caplog):
    session = make_session(rsa_pem)
    attach_stub(session, 403, json.dumps({"message": "Profile is disabled"}))

    with caplog.at_level(logging.ERROR, logger="iam_rolesanywhere_session"):
        with pytest.raises(CredentialsRetrievalError):
            fetch_credentials(session)

    assert "Profile is disabled" in caplog.text


# --------------------------------------------------------------------------
# Public API surface
# --------------------------------------------------------------------------


def test_all_is_explicit():
    assert iam_rolesanywhere_session.__all__ == sorted(
        iam_rolesanywhere_session.__all__
    )
    for name in iam_rolesanywhere_session.__all__:
        assert hasattr(iam_rolesanywhere_session, name), name


@pytest.mark.parametrize(
    "leaked", ["json", "logging", "base64", "hashlib", "Session", "SigV4Auth", "x509"]
)
def test_implementation_details_are_not_re_exported(leaked):
    """``import *`` used to drag the module's own imports into the public API."""
    assert leaked not in iam_rolesanywhere_session.__all__


def test_package_is_typed():
    import importlib.resources as resources

    assert resources.files("iam_rolesanywhere_session").joinpath("py.typed").is_file()


def test_exception_hierarchy():
    from iam_rolesanywhere_session import IAMRolesAnywhereError

    assert issubclass(CredentialsRetrievalError, IAMRolesAnywhereError)
    assert issubclass(UnsupportedPrivateKeyError, IAMRolesAnywhereError)
    assert issubclass(InvalidSessionDurationError, IAMRolesAnywhereError)
