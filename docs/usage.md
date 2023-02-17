---
title: Usage
---
# Configuration Parameters

IAMRoleAnywhereSession will take multiple arguments:

| Name             | Description                                                                                                                              | Type          | Default value |
|------------------|------------------------------------------------------------------------------------------------------------------------------------------|---------------|---------------|
| profile_arn      | The Amazon Resource Name (ARN) of the profile.                                                                                           | string        |     None      |
| role_arn         | The Amazon Resource Name (ARN) of the role to assume.                                                                                    | string        |     None      |
| trust_anchor_arn | The Amazon Resource Name (ARN) of the trust anchor.                                                                                      | string        |     None      |
| certificate      | The x509 certificate file, in PEM format.                                                                                                | path or bytes |     None      |
| private_key      | The certificate private key file, in PEM Format.                                                                                         | path or bytes |     None      |
| passphrase       | The passphrase use to decrypt private key file.                                                                                          | string        |     None      |
| region           | The name of the region where you configured IAM Roles Anywhere.                                                                          | string        |   us-east-1   |
| session_duration | The duration, in seconds, of the role session. The value specified can  range from 900 seconds (15 minutes) up to 3600 seconds (1 hour). | int           |     3600      |
| service_name     | An identifier for the service, used to build the botosession.                                                                            | string        | rolesanywhere |
| endpoint         | Roles Anywhere API endpoint to use                                                                                                       | string        | {service_name}.{region_name}.amazonaws.com' |


# Examples

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
