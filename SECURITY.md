# Reporting Security Issues

We take all security reports seriously. Thank you for improving the security of
this project.

## Reporting a Vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report suspected vulnerabilities to AWS Security via
[aws-security@amazon.com](mailto:aws-security@amazon.com), or through the
[AWS Vulnerability Reporting page](https://aws.amazon.com/security/vulnerability-reporting/).
Please do **not** create a public GitHub issue.

Include as much of the following as you can:

- The version of `iam_rolesanywhere_session` affected.
- A description of the issue and its impact.
- Steps to reproduce, ideally a minimal example.

## Handling Credentials

This library exchanges an X.509 certificate for temporary AWS credentials. Two
things are worth keeping in mind when using it:

- **Private keys.** A key passed as a filesystem path is read on every
  construction; a key passed as `bytes` lives in your process memory. Protect
  both with the same care as any long-lived secret.
- **Logging.** This package never logs credential material. It emits the
  credential expiry time at `DEBUG`, and service error messages at `ERROR`. If
  you wrap the returned session with your own request logging, make sure that
  code does not record the `Authorization` header or session tokens.
