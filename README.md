# IAM Roles Anywhere Session

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![PyPI version](https://badge.fury.io/py/iam-rolesanywhere-session.svg)](https://badge.fury.io/py/iam-rolesanywhere-session)
![Status](https://img.shields.io/pypi/status/iam-rolesanywhere-session.svg)

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)

This package provides an easy way to create a __refreshable__ boto3 Session with [AWS Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/APIReference/Welcome.html).

This package implements the algorithm described here: <https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html>.

## Requirements

- Python 3.8 or later
- Creation and configuration of a trust anchor. See [documentation](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/getting-started.html)
- Valid X.509 certificate, private key, and optionally a certificate chain file associated with your trust anchor

## Install

- From PyPi

```bash
pip install iam-rolesanywhere-session
```

- From source

```bash
git clone https://github.com/awslabs/iam-roles-anywhere-session.git
cd iam-roles-anywhere-session
python3 -m pip install ./
```

## Configuration

For this package to work you will need to have at your disposal your `certificate` and `private_key` file in a PEM format.

IAMRoleAnywhereSession will take multiple arguments:

| Name             | Description                                                                                                                              | Type          | Default value                                |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------- | -------------------------------------------- |
| profile_arn      | The Amazon Resource Name (ARN) of the profile.                                                                                           | string        | None                                         |
| role_arn         | The Amazon Resource Name (ARN) of the role to assume.                                                                                    | string        | None                                         |
| trust_anchor_arn | The Amazon Resource Name (ARN) of the trust anchor.                                                                                      | string        | None                                         |
| certificate      | The x509 certificate file, in PEM format.                                                                                                | path or bytes | None                                         |
| private_key      | The certificate private key file, in PEM Format.                                                                                         | path or bytes | None                                         |
| passphrase       | The passphrase use to decrypt private key file.                                                                                          | string        | None                                         |
| region           | The name of the region where you configured IAM Roles Anywhere.                                                                          | string        | us-east-1                                    |
| session_duration | The duration, in seconds, of the role session. The value specified can  range from 900 seconds (15 minutes) up to 3600 seconds (1 hour). | int           | 3600                                         |
| service_name     | An identifier for the service, used to build the botosession.                                                                            | string        | rolesanywhere                                |
| endpoint         | Roles Anywhere API endpoint to use                                                                                                       | string        | '{service_name}.{region_name}.amazonaws.com' |
| proxies          | Proxy endpoint(s) for use behind private networks with a proxy.                                                                          | dict          | `{}`                                         |
| proxies_config   | A dictionary of additional proxy configurations.                                                                                         | dict          | `{}`                                         |

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

# Documentation

You can find [here](https://awslabs.github.io/iam-rolesanywhere-session/) the complete documentation with additional usage and module reference.

## Contributing

Contributions are very welcome.
To learn more, see the [Contributor Guide](CONTRIBUTING.md).

## License

Distributed under the terms of the [Apache 2](LICENSE)
