
# Project: Automated S3 Public Access Auditor for Cloud Security Compliance
# File: auditor.py
# Author: Oyelekan Ogunrinu
# Date: 2025-08-13
#
# Description:
#   Main audit script. Connects to AWS S3 (or simulated test data) to:
#     - List all buckets in the account
#     - Retrieve each bucket’s Public Access Block settings, policy, and ACL
#     - Classify buckets as SAFE, RISKY, or PUBLIC based on simple rules
#     - Save results to a CSV file (and optional JSON)
#     - Print a short preview table to the console
#
#   This script is read-only — it does not change any bucket settings.
#   Works with live AWS credentials or offline test data.

"""
S3 Public Access Auditor (read-only)
- Lists buckets
- Checks Public Access Block (PAB)
- Reads bucket policy and ACL
- Classifies as: SAFE | RISKY | PUBLIC
- Writes CSV (+ JSON if requested)
"""

import argparse
import csv
import json
import logging
from typing import Dict, Any, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

# Prefer tabulate for a tidy preview; fall back to plain text if missing.
try:
    from tabulate import tabulate
except Exception:
    tabulate = None

from policy_checks import (
    policy_allows_public_read,
    policy_has_wildcard_principal,
    acl_has_public_grant,
)


# ---------- AWS helpers ----------

def get_session(profile: Optional[str]) -> boto3.session.Session:
    """Create a boto3 session (optionally with a named profile)."""
    return boto3.Session(profile_name=profile) if profile else boto3.Session()


def s3_client(session: boto3.session.Session, region: Optional[str] = None):
    """Create an S3 client. Region is optional for most calls."""
    return session.client("s3", region_name=region)


def get_bucket_region(s3, bucket_name: str) -> Optional[str]:
    """Return the bucket's region (defaults to us-east-1 if AWS returns None)."""
    try:
        resp = s3.get_bucket_location(Bucket=bucket_name)
        location_constraint = resp.get("LocationConstraint")
        return location_constraint or "us-east-1"
    except ClientError as err:
        logging.warning(f"{bucket_name}: get_bucket_location failed: {err}")
        return None


def get_public_access_block(s3, bucket_name: str) -> Dict[str, bool]:
    """
    Return dict with the 4 PAB flags.
    If not configured, all values are False.
    """
    keys = [
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    ]
    result = {key: False for key in keys}
    try:
        resp = s3.get_public_access_block(Bucket=bucket_name)
        cfg = resp.get("PublicAccessBlockConfiguration", {})
        for key in keys:
            result[key] = bool(cfg.get(key, False))
    except ClientError as err:
        code = err.response.get("Error", {}).get("Code", "")
        # If not configured, keep defaults; log other errors.
        if code not in {"NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock"}:
            logging.warning(f"{bucket_name}: get_public_access_block failed: {err}")
    return result


def get_bucket_policy_json(s3, bucket_name: str) -> Optional[Dict[str, Any]]:
    """Return policy as a dict, or None if missing or on error."""
    try:
        resp = s3.get_bucket_policy(Bucket=bucket_name)
        policy_text = resp.get("Policy")
        return json.loads(policy_text) if policy_text else None
    except ClientError as err:
        code = err.response.get("Error", {}).get("Code", "")
        if code != "NoSuchBucketPolicy":
            logging.debug(f"{bucket_name}: get_bucket_policy failed: {err}")
        return None


def get_bucket_acl(s3, bucket_name: str) -> Optional[Dict[str, Any]]:
    """Return bucket ACL dict, or None on error."""
    try:
        return s3.get_bucket_acl(Bucket=bucket_name)
    except ClientError as err:
        logging.debug(f"{bucket_name}: get_bucket_acl failed: {err}")
        return None


# ---------- Classification ----------

def classify_bucket(
    pab_flags: Dict[str, bool],
    policy: Optional[Dict[str, Any]],
    acl: Optional[Dict[str, Any]],
) -> Tuple[str, List[str]]:
    """
    Return (status, reasons).
    PUBLIC: policy or ACL exposes bucket
    RISKY : wildcard principal in policy or PAB not strict
    SAFE  : none of the above
    """
    reasons: List[str] = []

    # Policy signals
    policy_public, policy_reasons = policy_allows_public_read(policy) if policy else (False, [])
    if policy_public:
        reasons.extend(policy_reasons)

    wildcard_principal = policy_has_wildcard_principal(policy) if policy else False
    if wildcard_principal and not policy_public:
        reasons.append("policy has wildcard principal")

    # ACL signals
    acl_public, acl_reasons = acl_has_public_grant(acl) if acl else (False, [])
    if acl_public:
        reasons.extend(acl_reasons)

    # PAB strictness
    pab_is_strict = bool(pab_flags) and all(pab_flags.values())
    if not pab_is_strict:
        missing = [k for k, v in (pab_flags or {}).items() if not v]
        if missing:
            reasons.append("pab not strict: " + ", ".join(missing))

    # Final decision
    if policy_public or acl_public:
        status = "PUBLIC"
    elif wildcard_principal or (not pab_is_strict):
        status = "RISKY"
    else:
        status = "SAFE"

    return status, reasons


# ---------- CLI ----------

def main() -> None:
    parser = argparse.ArgumentParser(description="Audit S3 buckets for public access")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--region", help="Region (optional)")
    parser.add_argument("--out", default="s3_audit_report.csv", help="Output CSV path")
    parser.add_argument("--json", action="store_true", help="Also write JSON next to the CSV")
    parser.add_argument("--log", default="INFO", help="Log level (DEBUG, INFO, ...)")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log.upper(), logging.INFO),
        format="%(levelname)s %(message)s",
    )

    session = get_session(args.profile)
    s3 = s3_client(session, args.region)

    # List buckets
    try:
        resp = s3.list_buckets()
        bucket_names = [b["Name"] for b in resp.get("Buckets", [])]
    except ClientError as err:
        logging.error(f"list_buckets failed: {err}")
        return

    rows: List[Dict[str, Any]] = []
    for bucket_name in bucket_names:
        region = get_bucket_region(s3, bucket_name) or args.region
        pab = get_public_access_block(s3, bucket_name)
        policy = get_bucket_policy_json(s3, bucket_name)
        acl = get_bucket_acl(s3, bucket_name)
        status, reasons = classify_bucket(pab, policy, acl)

        rows.append({
            "bucket": bucket_name,
            "region": region or "",
            "BlockPublicAcls": pab.get("BlockPublicAcls", False),
            "IgnorePublicAcls": pab.get("IgnorePublicAcls", False),
            "BlockPublicPolicy": pab.get("BlockPublicPolicy", False),
            "RestrictPublicBuckets": pab.get("RestrictPublicBuckets", False),
            "policy_present": bool(policy),
            "acl_public": "yes" if (acl and acl_has_public_grant(acl)[0]) else "no",
            "status": status,
            "reasons": "; ".join(reasons) if reasons else "",
        })

    # CSV output
    if rows:
        with open(args.out, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        logging.info(f"wrote {args.out} with {len(rows)} rows")
    else:
        logging.info("no buckets found")

    # Optional JSON
    if args.json and rows:
        json_path = args.out.rsplit(".", 1)[0] + ".json"
        with open(json_path, "w") as jfh:
            json.dump(rows, jfh, indent=2)
        logging.info(f"wrote {json_path}")

    # Short preview
    if rows:
        columns = ["bucket", "region", "status", "acl_public", "policy_present"]
        preview = rows[:20]
        if tabulate:
            print(tabulate([[r[c] for c in columns] for r in preview], headers=columns, tablefmt="github"))
        else:
            print("\t".join(columns))
            for r in preview:
                print("\t".join(str(r[c]) for c in columns))
        if len(rows) > 20:
            print(f"... ({len(rows) - 20} more)")


if __name__ == "__main__":
    main()
