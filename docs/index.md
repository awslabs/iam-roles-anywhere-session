# IAM Roles Anywhere Session

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![PyPI version](https://badge.fury.io/py/iam-rolesanywhere-session.svg)](https://badge.fury.io/py/iam-rolesanywhere-session)
![Status](https://img.shields.io/pypi/status/iam-rolesanywhere-session.svg)

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)

This package provides an easy way to create a __refreshable__ boto3 Session with [AWS Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/APIReference/Welcome.html).

This package implements the algorithm described here: https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html.

## Requirements

- Python 3.5 or later
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
