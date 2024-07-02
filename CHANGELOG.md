# CHANGELOG.md

## 2.2.0

Improvements:

 - [#8](https://github.com/awslabs/iam-roles-anywhere-session/pull/8) Fix readme
 - [#10](https://github.com/awslabs/iam-roles-anywhere-session/pull/10) Add support for 'verify' parameter to specify path to trusted CA or allow insecure connections.


## 2.1.0

Improvements:

 - [#5](https://github.com/awslabs/iam-roles-anywhere-session/pull/5) Add proxy explicit proxy support
 - [#6](https://github.com/awslabs/iam-roles-anywhere-session/pull/6) Throw an error when credentials cannot be created


## 2.0.0

Packaging:

  - use pyproject.toml file
  - move source code to `src`
  - add pre-commit hooks

CI:

  - new workflow for building documentation

Features:

  - refactor code using botocore built-in signer and request mechanism

## 1.0.0 (Initial Release)
