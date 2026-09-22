# Throwaway IAM Roles Anywhere setup for live-testing this library.
#
# Creates a trust anchor from a self-signed CA bundle, a role that only IAM
# Roles Anywhere may assume, and a profile tying them together. Run
# `terraform destroy` when finished; nothing here is intended to persist.
#
# Cost: none. Trust anchors, profiles and roles are free. AWS Private CA is
# deliberately not used, as it bills per CA per month and a CERTIFICATE_BUNDLE
# trust anchor is sufficient.

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region

  # Left unset by default so the standard credential chain applies, which is
  # whatever the shell is already authenticated as. Set var.profile only to
  # target a specific named profile.
  profile = var.profile != "" ? var.profile : null
}

variable "region" {
  description = "Region in which to create the trust anchor and profile."
  type        = string

  # us-east-1 because IAM Roles Anywhere publishes a FIPS endpoint in only six
  # regions (us-east-1/2, us-west-1/2 and the two GovCloud regions). Using one
  # of them means a single stack covers every check, FIPS included.
  default = "us-east-1"
}

variable "profile" {
  description = "Local AWS profile to deploy with. Empty uses the ambient credentials."
  type        = string
  default     = ""
}

variable "ca_certificate_path" {
  description = "Path to the CA certificate PEM produced by make_certs.py."
  type        = string
  default     = "ca.pem"
}

variable "name_prefix" {
  description = "Prefix for the created resource names."
  type        = string
  default     = "iam-ra-smoketest"
}

resource "aws_rolesanywhere_trust_anchor" "this" {
  name    = "${var.name_prefix}-anchor"
  enabled = true

  source {
    source_type = "CERTIFICATE_BUNDLE"

    source_data {
      x509_certificate_data = file(var.ca_certificate_path)
    }
  }
}

# Only IAM Roles Anywhere may assume this role, and only by way of the trust
# anchor created above. Without the aws:SourceArn condition any trust anchor in
# the account could assume it.
data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    actions = [
      "sts:AssumeRole",
      "sts:TagSession",
      "sts:SetSourceIdentity",
    ]

    principals {
      type        = "Service"
      identifiers = ["rolesanywhere.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_rolesanywhere_trust_anchor.this.arn]
    }
  }
}

# No permissions policy is attached on purpose. The smoke test calls
# sts:GetCallerIdentity, which requires none, so a successful call proves the
# signing chain works while the role can do nothing at all.
resource "aws_iam_role" "this" {
  name               = "${var.name_prefix}-role"
  description        = "Throwaway role for iam-rolesanywhere-session live tests"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  # The effective session length is the lower of this and the profile's
  # duration_seconds. Left at the 3600 default, CreateSession rejects any longer
  # request with "DurationSeconds exceeds the MaxSessionDuration set for this
  # role", so both have to be raised to exercise the 12 hour maximum.
  max_session_duration = 43200
}

resource "aws_rolesanywhere_profile" "this" {
  name      = "${var.name_prefix}-profile"
  role_arns = [aws_iam_role.this.arn]
  enabled   = true

  # The profile duration caps what CreateSession will grant. 43200 is the
  # service maximum, which lets the smoke test exercise the upper bound.
  duration_seconds = 43200

  # Permit a caller-supplied roleSessionName so the smoke test can verify that
  # the request member is serialised under the right name.
  accept_role_session_name = true
}

output "trust_anchor_arn" {
  value = aws_rolesanywhere_trust_anchor.this.arn
}

output "profile_arn" {
  value = aws_rolesanywhere_profile.this.arn
}

output "role_arn" {
  value = aws_iam_role.this.arn
}

output "region" {
  value = var.region
}

output "smoke_test_command" {
  description = "Ready-to-run command for the live test."
  value = join(" ", [
    "python3 integration/smoke_test.py",
    "--profile-arn ${aws_rolesanywhere_profile.this.arn}",
    "--role-arn ${aws_iam_role.this.arn}",
    "--trust-anchor-arn ${aws_rolesanywhere_trust_anchor.this.arn}",
    "--certificate integration/client.pem",
    "--private-key integration/client.key",
    "--region ${var.region}",
  ])
}
