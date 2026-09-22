# CHANGELOG.md

## 3.0.0

Security:

- The `CreateSession` response body is no longer logged. It contains a live
  secret access key and session token, which were previously written to any
  handler attached at `DEBUG`.

Fixes:

- The signed `Host` header is now derived from the request URL instead of being
  hardcoded to `{service}.{region}.amazonaws.com`. The `endpoint` parameter had
  no effect on the signature, so every custom endpoint — FIPS, VPC endpoints,
  and the `aws-cn`, GovCloud and ISO partitions — produced a signature over a
  host that was never contacted, and was rejected by the service.
- Default endpoints are resolved per region and partition rather than assuming
  the `amazonaws.com` suffix.
- Requesting FIPS in a region without a FIPS endpoint now raises
  `UnsupportedFipsEndpointError` at construction. botocore synthesises a
  `<service>-fips.<region>` hostname for any region, so the request was
  otherwise signed correctly and then failed to resolve in DNS. IAM Roles
  Anywhere publishes FIPS endpoints in six regions; the supported set is read
  from the endpoint data botocore ships rather than hardcoded.
- HTTP errors are raised before the response body is parsed, so a non-JSON
  error page from a proxy no longer surfaces as a `JSONDecodeError` and mask the
  real status code. Thanks to @jeski-jit for diagnosing this in
  [#20](https://github.com/awslabs/iam-roles-anywhere-session/pull/20).
- `proxies` and `proxies_config` now reach the clients that `get_session()`
  hands out. They were passed to `set_config_variable()`, but `proxies` is not
  a botocore session variable, so the values were stored where no client read
  them and every downstream client had `config.proxies = None`. They are now
  applied through the session's default client config. Credential retrieval
  itself was always proxied correctly; only the returned session was affected,
  which is why environment-variable proxy setups masked this.
- `verify` now applies to the clients created from `get_session()`, not just to
  the credential request. A certificate bundle path is forwarded as botocore's
  `ca_bundle`; `verify=False` has no session-level or `Config` equivalent in
  botocore, so it is applied as each client is built. An explicit `verify=`
  passed to `client()` or `resource()` still wins. Passing `verify=False` now
  logs a warning, because it disables TLS verification for all AWS traffic from
  that session and not only for the credential endpoint.
- `ProxyConfig` declared the keys `http_proxy` and `https_proxy`, but botocore
  selects a proxy with `proxies.get(url.scheme)`, so the keys must be `http`
  and `https`. The working example in the docstring already used the correct
  form. Annotations only; no runtime behaviour depended on it.
- Replaced the deprecated `datetime.utcnow()` with a timezone-aware equivalent.
- Headers are replaced rather than appended when a request is signed, since
  `AWSRequest.headers` appends on assignment.
- Removed the mutable `{}` defaults for `proxies` and `proxies_config`.

Features:

- `role_session_name` sends `roleSessionName`, for CloudTrail attribution.
  Requires `acceptRoleSessionName` on the profile.
- `instance_properties` sends `instanceProperties`. Requires
  `requireInstanceProperties` on the profile.
- `use_fips_endpoint` selects the FIPS 140-3 validated endpoint.
- `session_duration` is validated against the 900–43200 second range the
  service accepts. The documented maximum was previously 3600. The effective
  ceiling for a request is the lower of the profile's `durationSeconds` and the
  role's `MaxSessionDuration`.

Breaking changes:

- Dropped Python 3.8, which reached end of life in October 2024. Requires 3.9+.
- `IAMRolesAnywhereError` is the new base for every error this package raises.
  The bare `Exception` previously raised on a failed `CreateSession` is now
  `CredentialsRetrievalError`, carrying `.status_code` and `.message`. Code
  catching `Exception` is unaffected.
- The unsupported-key `TypeError` is now `UnsupportedPrivateKeyError` and an
  out-of-range duration raises `InvalidSessionDurationError`. Both still
  subclass `TypeError` and `ValueError` respectively, so existing handlers work.
- `__init__` no longer does `from .iam_rolesanywhere_session import *`. The
  package now declares `__all__`, so incidental re-exports such as
  `iam_rolesanywhere_session.json` or `.Session` are gone. Import those from
  their own modules instead.

Packaging:

- Ships a PEP 561 `py.typed` marker, so the existing annotations are now
  visible to type checkers.
- Migrated to a PEP 639 SPDX license expression and `project.license-files`,
  replacing the deprecated license table and license classifier. Closes
  [#22](https://github.com/awslabs/iam-roles-anywhere-session/pull/22) by
  @FredeHoey.
- Publishing uses PyPI Trusted Publishing instead of a long-lived API token.
- Added a `pre-commit` CI job, so formatting can no longer drift on `main`.
  It invokes `pre-commit` directly, as `pre-commit/action` is maintenance-only.
- Updated every GitHub Action to its current major: `checkout` v4→v7,
  `setup-python` v5→v7, `upload-artifact` v4→v7, `cache` v4→v6,
  `configure-pages` v5→v6, `upload-pages-artifact` v3→v5, `deploy-pages` v4→v5.
  These are Node 24 runtime migrations with no input changes affecting this
  repository. Also bumped the `black` and `pre-commit-hooks` pins, and added the
  `github-actions` ecosystem to Dependabot so action versions stay current.
- Added `SECURITY.md`.
- Added markdownlint, configured in `.markdownlint-cli2.yaml` and enforced by a
  `pre-commit` hook. The repository had 179 markdown lint errors, 93 of them
  predating this release; it is now clean.

Testing:

- The unit suite grew from 5 tests to 80, and now covers the signing path
  including the ECDSA branch, which had no coverage at all. Three of the
  previous five tests had no assertions.
- Added `integration/`, a live end-to-end test. Terraform creates a disposable
  trust anchor from a self-signed CA bundle, and a smoke test runs the library
  against the real service. Every change in this release was verified that way,
  including a request signed for and accepted by
  `rolesanywhere-fips.us-east-1.amazonaws.com`, which the previous hardcoded
  `Host` header made impossible.

Documentation:

- `docs/index.md` claimed Python 3.5 or later.
- Every `trust_anchor_arn` example was malformed, with doubled colons around the
  account ID (`:eu-central-1::123::trust-anchor/`). Account IDs in examples now
  use the `111122223333` placeholder from the AWS documentation.
- `certificate_chain` was never listed in the parameter tables despite being a
  supported argument and mentioned under Requirements.
- Corrected the `certificate_chain='my_cert_cahin.pem'` typo, removed
  `get_session(region=...)` overrides copy-pasted into examples that were not
  about regions, and fixed the `passphrase` parameter name in `docs/index.md`
  (the argument is `private_key_passphrase`).
- The "Get Frozen Credentials" example read the auto-refreshing properties
  rather than calling `get_frozen_credentials()`; it now shows both.
- Documented `role_session_name`, `instance_properties`, `use_fips_endpoint`,
  partition handling, `verify`, and error handling, and added an `Exceptions`
  section to the module reference.

## 2.3.0

Improvements:

- [#16](https://github.com/awslabs/iam-roles-anywhere-session/pull/16) replace depreciated OpenSSL.crypto.sign by cryptography.hazmat.primitives.asymmetric by @mathieudupoux
- [#13](https://github.com/awslabs/iam-roles-anywhere-session/issues/13) fix

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
