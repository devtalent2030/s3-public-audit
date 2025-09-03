# tests/offline_policy_demo.py
# Quick offline checks for policy_checks.py (no AWS calls)

from src.policy_checks import (
    policy_allows_public_read,
    policy_has_wildcard_principal,
    acl_has_public_grant,
)
import csv

# sample inputs
SAFE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
        "Action": ["s3:GetObject"],
        "Resource": ["arn:aws:s3:::example-safe/*"]
    }]
}

RISKY_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": "*",
        "Action": ["s3:GetObject", "s3:ListBucket"],
        "Resource": ["arn:aws:s3:::example-risky", "arn:aws:s3:::example-risky/*"]
    }]
}

PRIVATE_ACL = {
    "Owner": {"ID": "abc"},
    "Grants": [
        {"Grantee": {"Type": "CanonicalUser", "ID": "abc"}, "Permission": "FULL_CONTROL"}
    ],
}

PUBLIC_ACL = {
    "Owner": {"ID": "abc"},
    "Grants": [
        {"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}
    ],
}

def classify(policy, acl):
    """Return (status, reasons) using simple rules."""
    reasons = []

    pol_public, pol_reasons = policy_allows_public_read(policy)
    if pol_public:
        reasons += pol_reasons

    wildcard = policy_has_wildcard_principal(policy)
    if wildcard and not pol_public:
        reasons.append("policy has wildcard principal")

    acl_public, acl_reasons = acl_has_public_grant(acl)
    if acl_public:
        reasons += acl_reasons

    if acl_public or pol_public:
        status = "PUBLIC"
    elif wildcard:
        status = "RISKY"
    else:
        status = "SAFE"

    return status, reasons

def main():
    cases = [
        ("example-safe", SAFE_POLICY, PRIVATE_ACL),
        ("example-risky", RISKY_POLICY, PRIVATE_ACL),
        ("example-public-acl", {}, PUBLIC_ACL),
    ]

    rows = []
    print("bucket,status,reasons")
    for b, p, a in cases:
        status, why = classify(p, a)
        reason_text = "; ".join(why) if why else "-"
        print(f"{b},{status},{reason_text}")
        rows.append({"bucket": b, "status": status, "reasons": reason_text})

    with open("audit_report_offline.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["bucket", "status", "reasons"])
        w.writeheader()
        w.writerows(rows)

    print("wrote audit_report_offline.csv")

if __name__ == "__main__":
    main()
