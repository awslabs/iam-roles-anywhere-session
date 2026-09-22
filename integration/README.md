# Live integration test

The unit suite stubs the HTTP layer, so it proves the signature is
self-consistent but not that IAM Roles Anywhere accepts it. This directory
creates a disposable trust anchor and runs the library against the real service.

Everything is created in **us-east-1**. IAM Roles Anywhere publishes a FIPS
endpoint in only six regions — `us-east-1`, `us-east-2`, `us-west-1`,
`us-west-2` and the two GovCloud regions — so deploying into one of them lets a
single stack cover every check. Override `region` if you prefer, but the FIPS
check will then need `--skip-fips`.

## Cost

Nothing. Trust anchors, profiles and IAM roles are free.

AWS Private CA is deliberately **not** used. A trust anchor accepts a
`CERTIFICATE_BUNDLE`, so a self-signed CA is sufficient, whereas Private CA
bills per CA per month.

## What gets created

| Resource     | Note                                                             |
| ------------ | ---------------------------------------------------------------- |
| Trust anchor | From the self-signed CA in `ca.pem`                              |
| IAM role     | Assumable only by IAM Roles Anywhere, only via that trust anchor |
| Profile      | 12 hour maximum duration, `roleSessionName` permitted            |

The role has **no permissions policy**. The smoke test calls
`sts:GetCallerIdentity`, which requires none, so a successful call proves the
signing chain works while the role itself can do nothing.

## Running it

Key material and Terraform state are gitignored. Never commit them.

```bash
# 1. Generate a throwaway CA and client certificate
python3 integration/make_certs.py --key-type rsa

# 2. Create the AWS resources (uses your ambient credentials)
cd integration
terraform init
terraform apply

# 3. Run the live test, using the command Terraform prints
terraform output -raw smoke_test_command
```

Run step 3 from the repository root with the package installed, for example
`pip install -e .`. Pass `-var="profile=<name>"` to `apply` to target a
specific named AWS profile instead of the ambient credentials.

To cover the elliptic curve signing path as well, regenerate with
`--key-type ec` and re-apply: the trust anchor bundle changes, so Terraform
replaces it.

## Cleaning up

```bash
cd integration
terraform destroy
rm -f integration/*.pem integration/*.key
```

## What the smoke test checks

1. `CreateSession` is accepted and STS resolves the assumed identity. This is
   the headline check: it proves the canonical request, the SigV4-X509
   signature and the signed `Host` header are all correct.
2. Refreshable credentials freeze correctly.
3. `roleSessionName` is accepted and appears in the STS identity.
4. `instanceProperties` is accepted.
5. A 43200 second duration is accepted, and one below 900 is rejected locally.
6. The FIPS endpoint resolves, signs and is accepted. Pass `--skip-fips` when
   deploying outside the six regions that publish one.
7. A rejected request raises `CredentialsRetrievalError` carrying the service's
   own status code and message.

Credential values are never printed; access keys and tokens are reported only
as a length.
