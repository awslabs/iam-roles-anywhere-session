#!/usr/bin/env python3
"""Live test of iam-rolesanywhere-session against the real service.

The unit suite stubs the HTTP layer, so it can prove the signature is
self-consistent but not that IAM Roles Anywhere accepts it. This script closes
that gap. It is the only way to validate the signing changes in 3.0.0, in
particular that the signed Host header matches the endpoint contacted.

Run it after `terraform apply`; the `smoke_test_command` output gives a
ready-made invocation.

No credential material is printed. Access keys and session tokens are reported
only as a length, never a value.
"""

import argparse
import logging
import sys

from iam_rolesanywhere_session import (
    CredentialsRetrievalError,
    IAMRolesAnywhereSession,
    InvalidSessionDurationError,
)

PASS = "PASS"
FAIL = "FAIL"
results = []


def check(name, fn):
    """Run one check, recording the outcome rather than aborting the run."""
    try:
        detail = fn()
    except Exception as exc:  # noqa: BLE001 - a live test reports, never crashes
        results.append((FAIL, name, f"{type(exc).__name__}: {exc}"))
        print(f"  {FAIL}  {name}\n        {type(exc).__name__}: {exc}")
        return False
    results.append((PASS, name, detail))
    print(f"  {PASS}  {name}" + (f"\n        {detail}" if detail else ""))
    return True


def session_kwargs(args, **overrides):
    kwargs = dict(
        profile_arn=args.profile_arn,
        role_arn=args.role_arn,
        trust_anchor_arn=args.trust_anchor_arn,
        certificate=args.certificate,
        private_key=args.private_key,
        region=args.region,
    )
    kwargs.update(overrides)
    return kwargs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile-arn", required=True)
    parser.add_argument("--role-arn", required=True)
    parser.add_argument("--trust-anchor-arn", required=True)
    parser.add_argument("--certificate", required=True, help="Client certificate PEM.")
    parser.add_argument("--private-key", required=True, help="Client private key PEM.")
    parser.add_argument("--region", default="eu-central-1")
    parser.add_argument(
        "--skip-fips",
        action="store_true",
        help="Skip the FIPS endpoint check, which needs a FIPS-enabled region.",
    )
    parser.add_argument("--debug", action="store_true", help="Log at DEBUG.")
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    print("IAM Roles Anywhere live test")
    print(f"  region {args.region}\n")

    # 1. The headline check. A successful GetCallerIdentity means the canonical
    #    request, the SigV4-X509 signature and the signed Host header were all
    #    accepted by the service.
    print("Credential retrieval and signing")

    def base_call():
        session = IAMRolesAnywhereSession(**session_kwargs(args)).get_session()
        identity = session.client("sts").get_caller_identity()
        return f"assumed {identity['Arn']}"

    signing_ok = check("CreateSession is accepted, STS identity resolves", base_call)

    if not signing_ok:
        print(
            "\nThe base call failed, so later checks would only repeat the same\n"
            "error. Fix this first: it usually means the signature was rejected,\n"
            "the trust anchor does not match the certificate's CA, or the profile\n"
            "does not list the role."
        )
        return 1

    # 2. Credentials are usable and never logged as values.
    def frozen():
        creds = IAMRolesAnywhereSession(
            **session_kwargs(args)
        ).get_refreshable_credentials()
        frozen = creds.get_frozen_credentials()
        assert frozen.access_key and frozen.secret_key and frozen.token
        return (
            f"access_key {len(frozen.access_key)} chars, "
            f"token {len(frozen.token)} chars (values not shown)"
        )

    check("refreshable credentials freeze correctly", frozen)

    # 3. roleSessionName. The wire member name was taken from AWS's credential
    #    helper source, never from a real request, so this is the check that
    #    confirms it.
    def role_session_name():
        wanted = "smoketest-session"
        session = IAMRolesAnywhereSession(
            **session_kwargs(args, role_session_name=wanted)
        ).get_session()
        arn = session.client("sts").get_caller_identity()["Arn"]
        assert arn.endswith(f"/{wanted}"), f"session name absent from {arn}"
        return f"name appears in {arn}"

    check(
        "roleSessionName is accepted and reaches CloudTrail identity", role_session_name
    )

    # 4. instanceProperties. Only accepted when the profile allows it; a
    #    ValidationException here would mean the member name is wrong.
    def instance_properties():
        session = IAMRolesAnywhereSession(
            **session_kwargs(args, instance_properties={"workload": "smoketest"})
        ).get_session()
        session.client("sts").get_caller_identity()
        return "accepted"

    check("instanceProperties is accepted", instance_properties)

    # 5. Session duration bounds. 43200 is the service maximum and the profile
    #    is created with that ceiling.
    def max_duration():
        session = IAMRolesAnywhereSession(
            **session_kwargs(args, session_duration=43200)
        ).get_session()
        session.client("sts").get_caller_identity()
        return "43200 seconds accepted"

    check("session_duration at the 43200 maximum", max_duration)

    def rejects_bad_duration():
        try:
            IAMRolesAnywhereSession(**session_kwargs(args, session_duration=60))
        except InvalidSessionDurationError as exc:
            return str(exc)
        raise AssertionError("expected InvalidSessionDurationError")

    check("session_duration below 900 is rejected locally", rejects_bad_duration)

    # 6. FIPS endpoint. Proves the resolved FIPS host is both reachable and
    #    correctly signed, which the hardcoded Host header made impossible.
    if not args.skip_fips:

        def fips():
            session = IAMRolesAnywhereSession(
                **session_kwargs(args, use_fips_endpoint=True)
            )
            host = session.endpoint
            session.get_session().client("sts").get_caller_identity()
            return f"signed and reached {host}"

        check("FIPS endpoint resolves, signs and is accepted", fips)

    # 7. Error path. A real service error must surface as a typed exception
    #    carrying the service's own message, not a JSON decode failure.
    def error_path():
        bad = (
            args.profile_arn.rsplit("/", 1)[0] + "/00000000-0000-0000-0000-000000000000"
        )
        try:
            IAMRolesAnywhereSession(
                **session_kwargs(args, profile_arn=bad)
            ).get_session().client("sts").get_caller_identity()
        except CredentialsRetrievalError as exc:
            assert exc.status_code, "no status code recorded"
            return f"HTTP {exc.status_code}: {exc.message}"
        raise AssertionError("expected CredentialsRetrievalError for a bogus profile")

    check("a rejected request raises CredentialsRetrievalError", error_path)

    failures = [r for r in results if r[0] == FAIL]
    print(f"\n{len(results) - len(failures)}/{len(results)} checks passed")
    if failures:
        print("\nFailed:")
        for _, name, detail in failures:
            print(f"  - {name}: {detail}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
