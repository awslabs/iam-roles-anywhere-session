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


class IAMRolesAnywhereError(Exception):
    """Base class for every error raised by this package."""


class CredentialsRetrievalError(IAMRolesAnywhereError):
    """Raised when IAM Roles Anywhere does not return usable credentials.

    Args:
        status_code (int): HTTP status code returned by the `CreateSession` call.
        message (str): Error detail reported by the service, or a description of
            why the response could not be interpreted.
    """

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(f"CreateSession failed (HTTP {status_code}): {message}")


class UnsupportedPrivateKeyError(IAMRolesAnywhereError, TypeError):
    """Raised when the supplied private key is neither RSA nor elliptic curve.

    Also inherits :class:`TypeError` so that callers written against v2, which
    raised a bare ``TypeError`` here, keep working.
    """


class UnsupportedFipsEndpointError(IAMRolesAnywhereError, ValueError):
    """Raised when FIPS is requested in a region that has no FIPS endpoint.

    botocore synthesises a ``<service>-fips.<region>`` hostname for any region,
    including those where no such endpoint exists, so without this check the
    request would be signed correctly and then fail to resolve in DNS.

    Args:
        service_name (str): Service identifier, normally ``rolesanywhere``.
        region_name (str): Region that was requested.
        supported (tuple): Regions that do publish a FIPS endpoint.
    """

    def __init__(self, service_name: str, region_name: str, supported) -> None:
        self.service_name = service_name
        self.region_name = region_name
        self.supported = tuple(supported)
        super().__init__(
            f"{service_name} has no FIPS endpoint in {region_name}. "
            f"FIPS is available in: {', '.join(self.supported) or 'no regions'}."
        )


class InvalidSessionDurationError(IAMRolesAnywhereError, ValueError):
    """Raised when the requested session duration is outside the allowed range.

    Also inherits :class:`ValueError` for consistency with other argument
    validation errors.
    """
