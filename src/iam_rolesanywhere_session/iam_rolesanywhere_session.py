"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License").
You may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import base64
import hashlib
import json
import logging
from datetime import datetime, timezone
from functools import lru_cache
from typing import Dict, List, Literal, Optional, TypedDict, Union
from urllib.parse import urlsplit

from boto3.session import Session
from botocore.auth import SIGV4_TIMESTAMP, SigV4Auth
from botocore.awsrequest import AWSRequest, AWSResponse
from botocore.config import Config
from botocore.credentials import DeferredRefreshableCredentials
from botocore.exceptions import BotoCoreError
from botocore.httpsession import URLLib3Session
from botocore.loaders import create_loader
from botocore.session import get_session as get_botocore_session
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.hashes import SHA256

from .exceptions import (
    CredentialsRetrievalError,
    UnsupportedFipsEndpointError,
    UnsupportedPrivateKeyError,
)

log = logging.getLogger(__name__)


class IAMCredentials(TypedDict):
    """IAMCredentials."""

    access_key: str
    secret_key: str
    token: str
    expiry_time: str


# "total=False" marks every key optional. Without it a TypedDict requires all
# of its keys, so passing only {"https": ...} would be reported as an error by
# type checkers. Python 3.11 spells this per-key as NotRequired[...], which is
# clearer, but this package supports 3.9.
class ProxyConfig(TypedDict, total=False):
    """A dictionary of proxy servers, keyed by the URL scheme they apply to.

    botocore selects a proxy with ``proxies.get(url.scheme)``, so the keys are
    the schemes themselves rather than environment-variable style names.

    Attributes:
        http: Proxy server, with port, for plain HTTP destinations.
        https: Proxy server, with port, for HTTPS destinations.

    Examples:
        `{'https': "http://URL:PORT", 'http': "http://URL:PORT"}`
    """

    http: str
    https: str


class AdditionalProxyConfig(TypedDict, total=False):
    """A dictionary of additional proxy configurations.

    Attributes:
        proxy_ca_bundle: The path to a custom certificate bundle to use when
            establishing SSL/TLS connections with the proxy.
        proxy_client_cert: The path to a certificate for proxy TLS client
            authentication. A `str` is treated as the path to the client
            certificate. A two element tuple is interpreted as the path to the
            client certificate followed by the path to its key.
        proxy_use_forwarding_for_https: For HTTPS proxies, forward requests to
            HTTPS destinations with an absolute URI. We strongly recommend using
            this option only with trusted or corporate proxies.
    """

    proxy_ca_bundle: str
    proxy_client_cert: Union[str, tuple]
    proxy_use_forwarding_for_https: bool


def _set_header(request: AWSRequest, name: str, value: str) -> None:
    """Set a header on a request, replacing any value already present.

    ``AWSRequest.headers`` derives from :class:`email.message.Message`, whose
    ``__setitem__`` appends instead of replacing. Assigning directly would
    therefore emit duplicate headers if a request were signed more than once,
    which would in turn invalidate the signature.

    Args:
        request (AWSRequest): Request to modify in place.
        name (str): Header name.
        value (str): Header value.
    """

    if name in request.headers:
        del request.headers[name]
    request.headers[name] = value


@lru_cache(maxsize=None)
def _fips_regions(service_name: str) -> frozenset:
    """Regions where botocore's endpoint data declares a FIPS variant.

    Read from the endpoint data shipped with botocore rather than hardcoded, so
    the set stays current as regions gain FIPS endpoints.

    Args:
        service_name (str): Service identifier, normally ``rolesanywhere``.

    Returns:
        frozenset: Region names offering a FIPS endpoint for the service.
    """

    data = create_loader().load_data("endpoints")
    regions = set()
    for partition in data.get("partitions", []):
        service = partition.get("services", {}).get(service_name) or {}
        for region, config in service.get("endpoints", {}).items():
            if any("fips" in v.get("tags", []) for v in config.get("variants", [])):
                regions.add(region)
    return frozenset(regions)


@lru_cache(maxsize=None)
def _resolve_endpoint(
    service_name: str, region_name: str, use_fips_endpoint: bool = False
) -> str:
    """Resolve the service hostname for a region, honouring AWS partitions.

    Resolution is delegated to botocore by constructing a throwaway client, so
    that FIPS endpoints and the non-commercial partitions (``aws-cn``,
    ``aws-us-gov``, the ISO partitions) stay correct without reimplementing the
    endpoint ruleset here. No credentials are required, requested, or used.

    Falls back to the commercial partition suffix when botocore does not know
    the service, which can happen if ``service_name`` has been overridden.

    Args:
        service_name (str): Service identifier, normally ``rolesanywhere``.
        region_name (str): Region in which IAM Roles Anywhere is configured.
        use_fips_endpoint (bool): Request the FIPS 140-3 validated endpoint.

    Raises:
        UnsupportedFipsEndpointError: FIPS was requested in a region without a
            FIPS endpoint. botocore would otherwise synthesise a hostname that
            does not resolve.

    Returns:
        str: Hostname to call, without scheme or path.
    """

    if use_fips_endpoint:
        supported = _fips_regions(service_name)
        if region_name not in supported:
            raise UnsupportedFipsEndpointError(
                service_name,
                region_name,
                sorted(r for r in supported if not r.startswith("fips-")),
            )

    # Only pass a config when FIPS is explicitly requested, so that the
    # AWS_USE_FIPS_ENDPOINT environment variable and shared config keep working.
    config = Config(use_fips_endpoint=True) if use_fips_endpoint else None
    try:
        client = get_botocore_session().create_client(
            service_name, region_name=region_name, config=config
        )
    except BotoCoreError:
        return f"{service_name}.{region_name}.amazonaws.com"
    return urlsplit(client.meta.endpoint_url).netloc


def _error_message(response: AWSResponse) -> str:
    """Extract a human readable error from a failed response, if possible.

    The service normally returns a JSON body with a ``message`` key, but errors
    raised by an intervening proxy or load balancer are frequently HTML or
    empty. Those must not mask the underlying status code.

    Args:
        response (AWSResponse): Failed response.

    Returns:
        str: Best available description of the failure.
    """

    try:
        body = json.loads(response.text)
    except ValueError:
        return response.text.strip() or "<empty response body>"

    if isinstance(body, dict):
        for key in ("message", "Message", "__type"):
            if key in body:
                return str(body[key])
    return response.text.strip() or "<empty response body>"


class _SessionWithVerify(Session):
    """A boto3 session that applies a default ``verify`` to the clients it makes.

    ``verify`` is a per-client argument in botocore: there is no session variable
    or :class:`~botocore.config.Config` option for it. A certificate bundle path
    can be forwarded as ``ca_bundle``, but ``verify=False`` has no session-level
    equivalent at all, so the only way to honour it for every client is to
    supply it as each client is constructed.

    An explicit ``verify`` passed to :meth:`client` or :meth:`resource` still
    takes precedence.
    """

    def __init__(
        self, *args, default_verify: Optional[Union[str, bool]] = None, **kwargs
    ):
        super().__init__(*args, **kwargs)
        self._default_verify = default_verify

    def client(self, *args, **kwargs):
        if self._default_verify is not None:
            kwargs.setdefault("verify", self._default_verify)
        return super().client(*args, **kwargs)

    def resource(self, *args, **kwargs):
        if self._default_verify is not None:
            kwargs.setdefault("verify", self._default_verify)
        return super().resource(*args, **kwargs)


class IAMRolesAnywhereSession:
    def __init__(
        self,
        profile_arn: str,
        role_arn: str,
        trust_anchor_arn: str,
        certificate: Union[str, bytes],
        private_key: Union[str, bytes],
        certificate_chain: Optional[Union[str, bytes]] = None,
        private_key_passphrase: Optional[str] = None,
        session_duration: int = 3600,
        region: str = "us-east-1",
        service_name: str = "rolesanywhere",
        endpoint: Optional[str] = None,
        verify: Optional[Union[str, bool]] = True,
        proxies: Optional[ProxyConfig] = None,
        proxies_config: Optional[AdditionalProxyConfig] = None,
        use_fips_endpoint: bool = False,
    ) -> None:
        # IAM Roles Anywhere variables

        self.profile_arn = profile_arn
        self.role_arn = role_arn
        self.trust_anchor_arn = trust_anchor_arn
        self.session_duration = session_duration
        self.region_name = region
        self.service_name = service_name
        self.endpoint = endpoint or _resolve_endpoint(
            service_name, region, use_fips_endpoint
        )

        # Certificates loading
        self.certificate = certificate
        self.certificate_chain = certificate_chain

        # Private key loading
        self.private_key_passphrase = private_key_passphrase
        self.private_key = private_key

        self.proxies = proxies or {}
        self.proxies_config = proxies_config or {}
        self.verify = verify
        if verify is False:
            log.warning(
                "TLS certificate verification is disabled. This applies to the "
                "IAM Roles Anywhere credential request and to every client "
                "created from the session returned by get_session()."
            )
        self._session = URLLib3Session(
            proxies=self.proxies, proxies_config=self.proxies_config, verify=verify
        )

        self._request_signer = IAMRolesAnywhereSigner(
            certificate=self.certificate,
            private_key=self.private_key,
            certificate_chain=self.certificate_chain,
            private_key_passphrase=self.private_key_passphrase,
            region=self.region_name,
            service_name=self.service_name,
        )

    def get_session(self, **kwargs) -> Session:
        """Get a botocore session

        Args:
            kwargs (dict): Key value of configuration parameter for Session object

        Returns:
            Session: Botocore session object
        """
        session = get_botocore_session()
        session._credentials = self.get_refreshable_credentials()

        # Default session region
        session.set_config_variable("region", self.region_name)

        # Proxy settings have to travel through the default client config.
        # "proxies" is not a botocore session variable, so set_config_variable
        # would store it somewhere no client ever reads.
        if self.proxies or self.proxies_config:
            session.set_default_client_config(
                Config(proxies=self.proxies, proxies_config=self.proxies_config)
            )

        # A certificate bundle path belongs in ca_bundle, which botocore applies
        # to every client. verify=False has no session-level equivalent and is
        # handled per client by _SessionWithVerify instead.
        if isinstance(self.verify, str):
            session.set_config_variable("ca_bundle", self.verify)

        for k, v in kwargs.items():
            session.set_config_variable(k, v)

        # verify=True is already botocore's default, so leave those sessions
        # completely untouched.
        return _SessionWithVerify(
            botocore_session=session,
            default_verify=None if self.verify is True else self.verify,
        )

    def get_refreshable_credentials(self) -> DeferredRefreshableCredentials:
        """Return refreshable credentials

        Returns:
            DeferredRefreshableCredentials: set credentials needed to authentificate requests. Credentials will be auto refreshed when needed.
        """

        return DeferredRefreshableCredentials(
            refresh_using=self.__get_credentials, method="custom-roles-anywhere"
        )

    def __get_credentials(self) -> IAMCredentials:
        """Compute and make the request to rolesanywhere endpoint to retrieve IAM Credentials

        Raises:
            CredentialsRetrievalError: The service returned an error status, an
                unparseable body, or a body without a credential set.

        Returns:
            dict: Dict of AWS Credentials acquired from rolesanywhere: {
                "access_key": accessKeyId,
                "secret_key": secretAccessKey,
                "token": sessionToken,
                "expiry_time": expirationTime,
            }
        """

        url = f"https://{self.endpoint}/sessions"

        # Generate a HTTP Request
        data = {
            "durationSeconds": self.session_duration,
            "profileArn": self.profile_arn,
            "roleArn": self.role_arn,
            "trustAnchorArn": self.trust_anchor_arn,
        }

        credentials_request = AWSRequest(method="POST", url=url, data=json.dumps(data))

        # Add auth to request
        self._request_signer.add_auth(credentials_request)

        # Make the request
        credentials_request_resp: AWSResponse = self._session.send(
            credentials_request.prepare()
        )

        # NOTE: a successful response body contains live AWS credentials. It must
        # never be logged, at any level.
        if credentials_request_resp.status_code > 299:
            message = _error_message(credentials_request_resp)
            log.error("IAM Roles Anywhere CreateSession failed: %s", message)
            raise CredentialsRetrievalError(
                credentials_request_resp.status_code, message
            )

        try:
            payload = json.loads(credentials_request_resp.text)
        except ValueError as exc:
            raise CredentialsRetrievalError(
                credentials_request_resp.status_code,
                "response body is not valid JSON",
            ) from exc

        try:
            aws_creds = payload["credentialSet"][0]["credentials"]
        except (IndexError, KeyError, TypeError) as exc:
            raise CredentialsRetrievalError(
                credentials_request_resp.status_code,
                "response did not contain a credential set",
            ) from exc

        log.debug(
            "Retrieved IAM Roles Anywhere credentials expiring at %s",
            aws_creds.get("expiration"),
        )

        return {
            "access_key": aws_creds.get("accessKeyId"),
            "secret_key": aws_creds.get("secretAccessKey"),
            "token": aws_creds.get("sessionToken"),
            "expiry_time": aws_creds.get("expiration"),
        }


class IAMRolesAnywhereSigner(SigV4Auth):
    def __init__(
        self,
        certificate: Union[str, bytes],
        private_key: Union[str, bytes],
        certificate_chain: Optional[Union[str, bytes]] = None,
        private_key_passphrase: Optional[str] = None,
        region: str = "us-east-1",
        service_name: str = "rolesanywhere",
    ) -> None:
        # Certificates loading
        self.certificate = self.__load_certificate(certificate)
        self.certificate_chain = (
            self.__load_certificate_chain(certificate_chain)
            if certificate_chain
            else None
        )

        # Private key loading
        self.private_key_passphrase = (
            private_key_passphrase.encode() if private_key_passphrase else None
        )
        self.private_key = self.__load_private_key(
            private_key, self.private_key_passphrase
        )

        super().__init__(
            credentials=None, service_name=service_name, region_name=region
        )

    def add_auth(self, request: AWSRequest) -> None:
        datetime_now = datetime.now(timezone.utc)
        request.context["timestamp"] = datetime_now.strftime(SIGV4_TIMESTAMP)

        self._modify_request_before_signing(request)
        canonical_request = self.canonical_request(request)

        log.debug("Calculating signature using v4 auth.")
        log.debug("CanonicalRequest:\n%s", canonical_request)
        string_to_sign = self.string_to_sign(request, canonical_request)

        log.debug("StringToSign:\n%s", string_to_sign)

        signature = self.signature(string_to_sign)
        log.debug("Signature:\n%s", signature)

        self._inject_signature_to_request(request, signature)

    def _inject_signature_to_request(
        self, request: AWSRequest, signature: str
    ) -> AWSRequest:
        x509_serial_number = "%d" % self.certificate.serial_number

        auth_str = [
            f"{self.algorithm} Credential={x509_serial_number}/%s" % self.scope(request)
        ]
        headers_to_sign = self.headers_to_sign(request)
        auth_str.append(f"SignedHeaders={self.signed_headers(headers_to_sign)}")
        auth_str.append("Signature=%s" % signature)
        _set_header(request, "Authorization", ", ".join(auth_str))
        return request

    def signature(self, string_to_sign: str, _=None) -> str:
        if isinstance(self.private_key, RSAPrivateKey):
            return self.private_key.sign(
                data=(string_to_sign).encode("utf-8"),
                padding=PKCS1v15(),
                algorithm=SHA256(),
            ).hex()
        else:
            return self.private_key.sign(
                (string_to_sign).encode("utf-8"), ECDSA(SHA256())
            ).hex()

    def scope(self, request: AWSRequest) -> str:
        scope = []
        scope.append(request.context["timestamp"][0:8])
        scope.append(self._region_name)
        scope.append(self._service_name)
        scope.append("aws4_request")
        return "/".join(scope)

    def string_to_sign(self, request: AWSRequest, canonical_request: str) -> str:
        """
        Return the canonical StringToSign as well as a dict
        containing the original version of all headers that
        were included in the StringToSign.
        """
        sts = [self.algorithm]
        sts.append(request.context["timestamp"])  # amz date
        sts.append(self.credential_scope(request))
        sts.append(hashlib.sha256(canonical_request.encode("utf-8")).hexdigest())
        return "\n".join(sts)

    def _modify_request_before_signing(self, request: AWSRequest) -> None:
        # Sign the host that is actually being contacted. Deriving it from the
        # request URL keeps custom, FIPS, VPC and non-commercial partition
        # endpoints working; a hardcoded host would be signed but not reached,
        # so the service would reject the signature.
        _set_header(request, "Host", urlsplit(request.url).netloc)
        _set_header(request, "Content-Type", "application/x-amz-json-1.0")
        self._set_necessary_date_headers(request)
        _set_header(request, "X-Amz-X509", self.__encode_to_der(self.certificate))

        if self.certificate_chain is not None:
            _set_header(
                request,
                "X-Amz-X509-Chain",
                self.__encode_to_der(self.certificate_chain),
            )

    @staticmethod
    def __encode_to_der(cert: Union[x509.Certificate, List[x509.Certificate]]) -> str:
        """Encode certificate or chain to der

        Args:
            cert (Union[x509.Certificate, List[x509.Certificate]]): Representation of the certificate(s) in PEM format.

        Returns:
            str: return the certificate(s) encoded in der format
        """

        def encode_der(certificate: x509.Certificate) -> str:
            return (
                base64.b64encode(certificate.public_bytes(serialization.Encoding.DER))
                .decode("utf-8")
                .strip()
            )

        if isinstance(cert, x509.Certificate):
            return encode_der(cert)

        _certs = [encode_der(crt) for crt in cert]
        return ",".join(_certs)

    @staticmethod
    def __load_certificate_chain(
        certificate_chain: Union[str, bytes],
    ) -> List[x509.Certificate]:
        """Load a certificate chain

        Args:
            certificate_chain (Union[str, bytes]): Representation of the certificate chain in PEM format.

        Returns:
            List[x509.Certificate]: return a list of certificate
        """

        if isinstance(certificate_chain, bytes):
            return x509.load_pem_x509_certificates(certificate_chain)

        with open(certificate_chain, "rb") as cert_chain_pem_file:
            return x509.load_pem_x509_certificates(cert_chain_pem_file.read())

    @staticmethod
    def __load_certificate(certificate: Union[str, bytes]) -> x509.Certificate:
        """Load the certificate

        Args:
            certificate (Union[str, bytes]): Representation of the certificate in PEM format.

        Returns:
            x509.Certificate: return the certificate
        """
        if isinstance(certificate, bytes):
            return x509.load_pem_x509_certificate(certificate, default_backend())

        with open(certificate, "rb") as cert_pem_file:
            return x509.load_pem_x509_certificate(
                cert_pem_file.read(), default_backend()
            )

    @staticmethod
    def __load_private_key(
        private_key: Union[str, bytes], passphrase: Optional[bytes] = None
    ) -> Union[RSAPrivateKey, EllipticCurvePrivateKey]:
        """Load the private key

        Args:
            private_key (Union[str, bytes]): Representation of the private key in PEM format.
            passphrase (Optional[bytes]): Passphrase protecting the key, if any.

        Raises:
            UnsupportedPrivateKeyError: The key is neither RSA nor elliptic curve.

        Returns:
            Union[RSAPrivateKey, EllipticCurvePrivateKey]: the loaded private key
        """
        if isinstance(private_key, bytes):
            loaded_pk = serialization.load_pem_private_key(
                private_key, password=passphrase
            )
        else:
            with open(private_key, "rb") as pk_file:
                loaded_pk = serialization.load_pem_private_key(
                    pk_file.read(), password=passphrase
                )
        if not isinstance(loaded_pk, (RSAPrivateKey, EllipticCurvePrivateKey)):
            raise UnsupportedPrivateKeyError(
                "Unsupported private key type: Must be RSA or ECDSA."
            )
        return loaded_pk

    @property
    def private_key_type(self) -> Literal["RSA", "ECDSA"]:
        return (
            "ECDSA" if isinstance(self.private_key, EllipticCurvePrivateKey) else "RSA"
        )

    @property
    def algorithm(self) -> str:
        return f"AWS4-X509-{self.private_key_type}-{self.certificate.signature_hash_algorithm.name.upper()}"
