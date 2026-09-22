---
title: Usage
---

## Minimal implementation

```python
from iam_rolesanywhere_session import IAMRolesAnywhereSession

roles_anywhere_session = IAMRolesAnywhereSession(
    profile_arn="arn:aws:rolesanywhere:eu-central-1:111122223333:profile/a6294488-77cf-4d4a-8c5c-40b96690bbf0",
    role_arn="arn:aws:iam::111122223333:role/IAMRolesAnywhere-01",
    trust_anchor_arn="arn:aws:rolesanywhere:eu-central-1:111122223333:trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539",
    certificate='certificate.pem',
    private_key='privkey.pem',
    region="eu-central-1"
).get_session()

s3 = roles_anywhere_session.client("s3")
print(s3.list_buckets())

```

## Use a different region for IAM Roles Anywhere and the session

```python
from iam_rolesanywhere_session import IAMRolesAnywhereSession

roles_anywhere_session = IAMRolesAnywhereSession(
    profile_arn="arn:aws:rolesanywhere:eu-central-1:111122223333:profile/a6294488-77cf-4d4a-8c5c-40b96690bbf0",
    role_arn="arn:aws:iam::111122223333:role/IAMRolesAnywhere-01",
    trust_anchor_arn="arn:aws:rolesanywhere:eu-central-1:111122223333:trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539",
    certificate='certificate.pem',
    private_key='privkey.pem',
    region="eu-central-1"
).get_session(region="eu-west-1")

s3 = roles_anywhere_session.client("s3")
print(s3.list_buckets())

```

## Private Key encoded with a passphrase

```python
from iam_rolesanywhere_session import IAMRolesAnywhereSession

roles_anywhere_session = IAMRolesAnywhereSession(
    profile_arn="arn:aws:rolesanywhere:eu-central-1:111122223333:profile/a6294488-77cf-4d4a-8c5c-40b96690bbf0",
    role_arn="arn:aws:iam::111122223333:role/IAMRolesAnywhere-01",
    trust_anchor_arn="arn:aws:rolesanywhere:eu-central-1:111122223333:trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539",
    certificate='certificate.pem',
    private_key='privkey.pem',
    private_key_passphrase="my_secured_passphrase",
    region="eu-central-1"
).get_session()

s3 = roles_anywhere_session.client("s3")
print(s3.list_buckets())
```

## Use a certificate chain

```python
from iam_rolesanywhere_session import IAMRolesAnywhereSession

roles_anywhere_session = IAMRolesAnywhereSession(
    profile_arn="arn:aws:rolesanywhere:eu-central-1:111122223333:profile/a6294488-77cf-4d4a-8c5c-40b96690bbf0",
    role_arn="arn:aws:iam::111122223333:role/IAMRolesAnywhere-01",
    trust_anchor_arn="arn:aws:rolesanywhere:eu-central-1:111122223333:trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539",
    certificate='certificate.pem',
    certificate_chain='my_cert_chain.pem',
    private_key='privkey.pem',
    private_key_passphrase="my_secured_passphrase",
    region="eu-central-1"
).get_session()

s3 = roles_anywhere_session.client("s3")
print(s3.list_buckets())
```

## Get Frozen Credentials

```python
from iam_rolesanywhere_session import IAMRolesAnywhereSession

creds = IAMRolesAnywhereSession(
    profile_arn="arn:aws:rolesanywhere:eu-central-1:111122223333:profile/a6294488-77cf-4d4a-8c5c-40b96690bbf0",
    role_arn="arn:aws:iam::111122223333:role/IAMRolesAnywhere-01",
    trust_anchor_arn="arn:aws:rolesanywhere:eu-central-1:111122223333:trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539",
    certificate='certificate.pem',
    certificate_chain='my_cert_chain.pem',
    private_key='privkey.pem',
    private_key_passphrase="my_secured_passphrase",
    region="eu-central-1"
).get_refreshable_credentials()

# These properties refresh on access, so they are always current.
ACCESS_KEY = creds.access_key
SECRET_KEY = creds.secret_key
TOKEN = creds.token

# For a consistent point-in-time snapshot of all three, freeze them together.
frozen = creds.get_frozen_credentials()
ACCESS_KEY, SECRET_KEY, TOKEN = frozen.access_key, frozen.secret_key, frozen.token
```

## Use proxy configuration

The `http_proxy`, `https_proxy` and `no_proxy` environment variables are
picked up automatically. Keys in `proxies` are URL schemes, so `http` and
`https` rather than the environment-variable names.

> Since 3.0.0 the proxy configuration is also applied to every client created
> from the returned session, not only to the credential request itself.

```python
from iam_rolesanywhere_session import IAMRolesAnywhereSession

roles_anywhere_session = IAMRolesAnywhereSession(
    profile_arn="arn:aws:rolesanywhere:eu-central-1:111122223333:profile/a6294488-77cf-4d4a-8c5c-40b96690bbf0",
    role_arn="arn:aws:iam::111122223333:role/IAMRolesAnywhere-01",
    trust_anchor_arn="arn:aws:rolesanywhere:eu-central-1:111122223333:trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539",
    certificate='certificate.pem',
    private_key='privkey.pem',
    region="eu-central-1",
    proxies={'https': "http://URL:PORT", 'http': "http://URL:PORT"}
).get_session()

s3 = roles_anywhere_session.client("s3")
print(s3.list_buckets())

```

## Attribute a session in CloudTrail

`role_session_name` requires the profile to have been created with
`acceptRoleSessionName` enabled, otherwise the service rejects the request.

```python
from iam_rolesanywhere_session import IAMRolesAnywhereSession

roles_anywhere_session = IAMRolesAnywhereSession(
    profile_arn="arn:aws:rolesanywhere:eu-central-1:111122223333:profile/a6294488-77cf-4d4a-8c5c-40b96690bbf0",
    role_arn="arn:aws:iam::111122223333:role/IAMRolesAnywhere-01",
    trust_anchor_arn="arn:aws:rolesanywhere:eu-central-1:111122223333:trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539",
    certificate='certificate.pem',
    private_key='privkey.pem',
    region="eu-central-1",
    role_session_name="batch-worker-07",
    instance_properties={"workload": "nightly-batch"},
).get_session()
```

## Use a FIPS endpoint

```python
roles_anywhere_session = IAMRolesAnywhereSession(
    ...,
    region="us-east-1",
    use_fips_endpoint=True,
).get_session()
```

FIPS endpoints exist only in US and Canada regions. Elsewhere botocore still
synthesises a `-fips` hostname, which will not resolve, so only enable this
where a FIPS endpoint actually exists.

Endpoints are otherwise resolved from the region, so the China (`aws-cn`),
GovCloud and ISO partitions work without passing `endpoint` explicitly. Pass
`endpoint` only to reach something botocore cannot resolve, such as a VPC
endpoint.

## Handle credential retrieval failures

```python
from iam_rolesanywhere_session import (
    CredentialsRetrievalError,
    IAMRolesAnywhereSession,
)

try:
    session = IAMRolesAnywhereSession(...).get_session()
    print(session.client("s3").list_buckets())
except CredentialsRetrievalError as error:
    print(f"HTTP {error.status_code}: {error.message}")
```

## Use a private certificate authority

`verify` accepts a path to a CA bundle, or `False` to skip verification. It is
applied to the IAM Roles Anywhere credential request *and* to every client the
returned session creates, so a corporate CA only needs to be named once.

```python
roles_anywhere_session = IAMRolesAnywhereSession(
    ...,
    verify="/etc/ssl/certs/corporate-ca.pem",
).get_session()

# Inherits the CA bundle above.
s3 = roles_anywhere_session.client("s3")

# An explicit value still takes precedence.
other = roles_anywhere_session.client("s3", verify="/etc/ssl/certs/other-ca.pem")
```

!!! warning
    `verify=False` disables TLS certificate verification for all AWS traffic
    from that session, not just the credential endpoint. Prefer pointing
    `verify` at the CA bundle your proxy presents.
