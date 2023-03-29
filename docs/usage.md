---
title: Usage
---
# Usages

## Minimal implementation

```python
from iam_rolesanywhere_session import IAMRolesAnywhereSession

roles_anywhere_session = IAMRolesAnywhereSession(
    profile_arn="arn:aws:rolesanywhere:eu-central-1:************:profile/a6294488-77cf-4d4a-8c5c-40b96690bbf0",
    role_arn="arn:aws:iam::************:role/IAMRolesAnywhere-01",
    trust_anchor_arn="arn:aws:rolesanywhere:eu-central-1::************::trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539",
    certificate='certificate.pem',
    private_key='privkey.pem',
    region="eu-central-1"
).get_session()

s3 = roles_anywhere_session.client("s3")
print(s3.list_buckets())

```

## Use a different region for IAM Roles Anywhere and the session.

```python
from iam_rolesanywhere_session import IAMRolesAnywhereSession

roles_anywhere_session = IAMRolesAnywhereSession(
    profile_arn="arn:aws:rolesanywhere:eu-central-1:************:profile/a6294488-77cf-4d4a-8c5c-40b96690bbf0",
    role_arn="arn:aws:iam::************:role/IAMRolesAnywhere-01",
    trust_anchor_arn="arn:aws:rolesanywhere:eu-central-1::************::trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539",
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
    profile_arn="arn:aws:rolesanywhere:eu-central-1:************:profile/a6294488-77cf-4d4a-8c5c-40b96690bbf0",
    role_arn="arn:aws:iam::************:role/IAMRolesAnywhere-01",
    trust_anchor_arn="arn:aws:rolesanywhere:eu-central-1::************::trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539",
    certificate='certificate.pem',
    private_key='privkey.pem',
    private_key_passphrase = "my_secured_passphrase",
    region="eu-central-1"
).get_session(region="eu-west-1")

s3 = roles_anywhere_session.client("s3")
print(s3.list_buckets())
```

## Use a certificate chain

```python
from iam_rolesanywhere_session import IAMRolesAnywhereSession

roles_anywhere_session = IAMRolesAnywhereSession(
    profile_arn="arn:aws:rolesanywhere:eu-central-1:************:profile/a6294488-77cf-4d4a-8c5c-40b96690bbf0",
    role_arn="arn:aws:iam::************:role/IAMRolesAnywhere-01",
    trust_anchor_arn="arn:aws:rolesanywhere:eu-central-1::************::trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539",
    certificate='certificate.pem',
    certificate_chain='my_cert_cahin.pem',
    private_key='privkey.pem',
    private_key_passphrase = "my_secured_passphrase",
    region="eu-central-1"
).get_session(region="eu-west-1")

s3 = roles_anywhere_session.client("s3")
print(s3.list_buckets())
```

## Get Frozen Credentials


```python
from iam_rolesanywhere_session import IAMRolesAnywhereSession

creds = IAMRolesAnywhereSession(
    profile_arn="arn:aws:rolesanywhere:eu-central-1:************:profile/a6294488-77cf-4d4a-8c5c-40b96690bbf0",
    role_arn="arn:aws:iam::************:role/IAMRolesAnywhere-01",
    trust_anchor_arn="arn:aws:rolesanywhere:eu-central-1::************::trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539",
    certificate='certificate.pem',
    certificate_chain='my_cert_cahin.pem',
    private_key='privkey.pem',
    private_key_passphrase = "my_secured_passphrase",
    region="eu-central-1"
).get_refreshable_credentials()

ACCESS_KEY = creds.access_key
SECRET_KEY = creds.secret_key
TOKEN = creds.token

```

## Use proxy configuration

Environment variables (`http_proxy`, `https_proxy` and `no_proxy`) are automatically used.

> Proxy configuration are automatically added to botocore session.

```python
from iam_rolesanywhere_session import IAMRolesAnywhereSession

roles_anywhere_session = IAMRolesAnywhereSession(
    profile_arn="arn:aws:rolesanywhere:eu-central-1:************:profile/a6294488-77cf-4d4a-8c5c-40b96690bbf0",
    role_arn="arn:aws:iam::************:role/IAMRolesAnywhere-01",
    trust_anchor_arn="arn:aws:rolesanywhere:eu-central-1::************::trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539",
    certificate='certificate.pem',
    private_key='privkey.pem',
    region="eu-central-1",
    proxies={'https': "http://URL:PORT", 'http': "http://URL:PORT"}
).get_session()

s3 = roles_anywhere_session.client("s3")
print(s3.list_buckets())

```
