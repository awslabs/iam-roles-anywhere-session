# Releasing

Notes for maintainers with release rights. Publishing uses
[PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/), so there is
no API token in the repository: PyPI verifies the workflow's OpenID Connect
identity at upload time and issues a short-lived token in exchange.

## One-time setup

Trusted publishing must be registered on each index before it will accept an
upload. Until that is done the publish workflows fail with a trusted publishing
exchange error, because they no longer send a password.

Registering requires **owner** or **maintainer** on the project.

### 1. TestPyPI

The project already exists on TestPyPI, so add a publisher under the project's
own settings rather than a *pending* publisher. Pending publishers are only for
names that have never been uploaded.

Go to
[test.pypi.org publishing settings](https://test.pypi.org/manage/project/iam-rolesanywhere-session/settings/publishing/)
and add a GitHub publisher:

| Field         | Value                             |
| ------------- | --------------------------------- |
| Owner         | `awslabs`                         |
| Repository    | `iam-roles-anywhere-session`      |
| Workflow name | `python-publish-release-test.yml` |
| Environment   | *leave empty*                     |

Leave the environment empty: the `Upload Python Test Package` job does not
declare one, and a registered environment must match exactly.

### 2. PyPI

Add a publisher under
[pypi.org publishing settings](https://pypi.org/manage/project/iam-rolesanywhere-session/settings/publishing/):

| Field         | Value                        |
| ------------- | ---------------------------- |
| Owner         | `awslabs`                    |
| Repository    | `iam-roles-anywhere-session` |
| Workflow name | `python-publish-release.yml` |
| Environment   | `prod`                       |

`prod` must match the `environment:` on the `deploy` job in
`.github/workflows/python-publish-release.yml`.

### 3. Retire the old tokens

Keep the `PYPI_API_TOKEN` and `TEST_PYPI_API_TOKEN` repository secrets until a
real release has succeeded. Once it has, revoke both on PyPI and delete them
from the repository settings. They are no longer referenced by any workflow.

## Verifying the setup on TestPyPI

Prove the OIDC exchange works before tagging a real release. TestPyPI is a
separate index, so this cannot affect the published package.

1. Confirm the version in `pyproject.toml` is not already on
   [TestPyPI](https://test.pypi.org/project/iam-rolesanywhere-session/#history).
   An index never allows a version to be replaced.
2. Run the **Upload Python Test Package** workflow from the Actions tab
   (`workflow_dispatch`).
3. Check the upload appears in the TestPyPI release history.
4. Install it in a throwaway environment:

   ```bash
   python3 -m venv /tmp/rc && /tmp/rc/bin/pip install \
     --index-url https://test.pypi.org/simple/ \
     --extra-index-url https://pypi.org/simple/ \
     iam-rolesanywhere-session
   /tmp/rc/bin/python -c "import iam_rolesanywhere_session as m; print(m.__all__)"
   ```

   The `--extra-index-url` is required because TestPyPI does not mirror
   `boto3`, `botocore` and `cryptography`.

## Cutting a release

1. Update `version` in `pyproject.toml` and add a `CHANGELOG.md` entry.
2. Merge to `main` and confirm **Python package & test** is green.
3. Publish a GitHub release with a tag matching the version.
4. The **Upload Python Package** workflow runs on release publication and
   uploads to PyPI.
5. Confirm the new version appears on
   [PyPI](https://pypi.org/project/iam-rolesanywhere-session/) and that the docs
   published to [GitHub Pages](https://awslabs.github.io/iam-roles-anywhere-session/).

## Troubleshooting

| Symptom                             | Cause                                                                         |
| ----------------------------------- | ----------------------------------------------------------------------------- |
| Trusted publishing exchange failure | No publisher registered, or owner, repository, workflow or environment differ |
| `File already exists`               | That version is already on the index; bump the version                        |
| Missing `id-token` permission       | The job needs `permissions: id-token: write`                                  |
| Works on TestPyPI but not PyPI      | Two separate registrations are required, one per index                        |
