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

#!/bin/env python3
import base64
import hashlib
import json
import logging
from datetime import datetime
from typing import List, Optional, TypedDict, Union

from boto3.session import Session
from botocore.auth import SIGV4_TIMESTAMP, SigV4Auth
from botocore.awsrequest import AWSRequest, AWSResponse
from botocore.credentials import DeferredRefreshableCredentials
from botocore.httpsession import URLLib3Session
from botocore.session import get_session as get_botocore_session
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from OpenSSL import crypto
from OpenSSL.crypto import PKey

log = logging.getLogger(__name__)


class IAMCredentials(TypedDict):
    """IAMCredentials."""

    access_key: str
    secret_key: str
    token: str
    expiry_time: str


class ProxyConfig(TypedDict):
    """A dictionary of proxy servers to use by protocol or
        endpoint

    Args:
        http_proxy (str): http proxy server with port
        https_proxy (str): https proxy server with port

    Examples:
        `{'https': "http://URL:PORT", 'http': "http://URL:PORT"}`
    """

    http_proxy: str
    https_proxy: str


class AdditionalProxyConfig(TypedDict):
    """A dictionary of additional proxy configurations.

    Args:
        * proxy_ca_bundle (str): -- The path to a custom certificate bundle to use
            when establishing SSL/TLS connections with proxy.
        * proxy_client_cert (str,tuple): -- The path to a certificate for proxy
          TLS client authentication.
          When a str is provided it is treated as a path to a proxy client
          certificate. When a two element tuple is provided, it will be
          interpreted as the path to the client certificate, and the path
          to the certificate key.
        * proxy_use_forwarding_for_http (bool): -- For HTTPS proxies,
          forward your requests to HTTPS destinations with an absolute
          URI. We strongly recommend you only use this option with
          trusted or corporate proxies. Value must be boolean.
    """

    proxy_ca_bundle: str
    proxy_client_cert: Union[str, tuple]
    proxy_use_forwarding_for_https: bool


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
        session_duration: Optional[int] = 3600,
        region: Optional[str] = "us-east-1",
        service_name: Optional[str] = "rolesanywhere",
        endpoint: Optional[str] = None,
        proxies: Optional[ProxyConfig] = {},
        proxies_config: Optional[AdditionalProxyConfig] = {},
    ) -> None:
        # IAM Roles Anywhere variables

        self.profile_arn = profile_arn
        self.role_arn = role_arn
        self.trust_anchor_arn = trust_anchor_arn
        self.session_duration = session_duration
        self.region_name = region
        self.service_name = service_name
        self.endpoint = (
            endpoint or f"{self.service_name}.{self.region_name}.amazonaws.com"
        )

        # Certificates loading
        self.certificate = certificate
        self.certificate_chain = certificate_chain

        # Private key loading
        self.private_key_passphrase = private_key_passphrase
        self.private_key = private_key

        self.proxies = proxies
        self.proxies_config = proxies_config
        self._session = URLLib3Session(
            proxies=self.proxies, proxies_config=self.proxies_config
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

        # Set proxy configuration
        session.set_config_variable("proxies", self.proxies)
        session.set_config_variable("proxies_config", self.proxies_config)

        for k, v in kwargs.items():
            session.set_config_variable(k, v)
        return Session(botocore_session=session)

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

        Returns:
            dict: Dict of AWS Credentials acquired from rolesanywhere: {
                "access_key": accessKeyId,
                "secret_key": secretAccessKey,
                "token": sessionToken,
                "expiry_time": expirationTime,
            }
        """

        method = "POST"

        url = f"https://{self.endpoint}/sessions"

        data = {
            "durationSeconds": self.session_duration,
            "profileArn": self.profile_arn,
            "roleArn": self.role_arn,
            "trustAnchorArn": self.trust_anchor_arn,
        }

        # Generate a HTTP Request
        credentials_request = AWSRequest(method=method, url=url, data=json.dumps(data))

        # Add auth to request
        self._request_signer.add_auth(credentials_request)

        # Make the request
        credentials_request_resp: AWSResponse = self._session.send(
            credentials_request.prepare()
        )

        log.debug(credentials_request_resp.text)

        # Load the results
        credentials_request_response_text = json.loads(credentials_request_resp.text)
        if credentials_request_resp.status_code > 299:
            log.error(credentials_request_response_text["message"])
            raise Exception(credentials_request_response_text["message"])
            
        aws_creds = (
            credentials_request_response_text
            .get("credentialSet")[0]
            .get("credentials")
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
        region: Optional[str] = "us-east-1",
        service_name: Optional[str] = "rolesanywhere",
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
        self.private_key_type = self.__get_privatekey_type()

        super().__init__(
            credentials=None, service_name=service_name, region_name=region
        )

    def add_auth(self, request: AWSRequest) -> None:
        datetime_now = datetime.utcnow()
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
        request.headers["Authorization"] = ", ".join(auth_str)
        return request

    def signature(self, string_to_sign) -> str:
        return crypto.sign(
            self.private_key, (string_to_sign).encode("utf-8"), "sha256"
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
        request.headers[
            "Host"
        ] = f"{self._service_name}.{self._region_name}.amazonaws.com"
        request.headers["Content-Type"] = "application/x-amz-json-1.0"
        self._set_necessary_date_headers(request)
        request.headers["X-Amz-X509"] = self.__encode_to_der(self.certificate)

        if self.certificate_chain is not None:
            request.headers["X-Amz-X509-Chain"] = self.__encode_to_der(
                self.certificate_chain
            )

    @staticmethod
    def __encode_to_der(cert: Union[x509.Certificate, List[x509.Certificate]]) -> str:
        """Encode certificate or chain to der

        Args:
            cert (Union[x509.Certificate, List[x509.Certificate]]): Representation of the certificate(s) in PEM format.

        Returns:
            str: return the certificate(s) encoded in der format
        """

        def encode_der(certificate):
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
        certificate_chain: Union[str, bytes]
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
        private_key: Union[str, bytes], passphrase: Optional[str] = None
    ) -> PKey:
        """Load the private key

        Args:
            private_key (Union[str, bytes]): Representation of the private key in PEM format.

        Returns:
            PKey: return a Pkey object
        """
        if isinstance(private_key, bytes):
            return crypto.load_privatekey(
                crypto.FILETYPE_PEM, private_key, passphrase=passphrase
            )
        with open(private_key, "rb") as private_key:
            return crypto.load_privatekey(
                crypto.FILETYPE_PEM, private_key.read(), passphrase=passphrase
            )

    def __get_privatekey_type(self) -> str:
        """Get the private key type and raise an error for unsupported type

        Raises:
            Exception: Private key is not supported
            Exception: The object provided is not a PKey object

        Returns:
            str: Type of the key, RSA or ECDSA.
        """
        if isinstance(self.private_key, PKey):
            if self.private_key.type() == crypto.TYPE_EC:
                return "ECDSA"
            elif self.private_key.type() == crypto.TYPE_RSA:
                return "RSA"
            else:
                raise Exception("Private Key type is not supported")
        else:
            raise Exception("Object is not a Pkey instance")

    @property
    def algorithm(self) -> str:
        return f"AWS4-X509-{self.private_key_type}-{self.certificate.signature_hash_algorithm.name.upper()}"
