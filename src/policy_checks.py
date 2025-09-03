# Project: Automated S3 Public Access Auditor for Cloud Security Compliance
# File: policy_checks.py
# Author: Oyelekan Ogunrinu
# Date: 2025-08-13
#
# Description:
#   Helper functions for auditor.py that inspect S3 bucket policies and ACLs
#   for signs of public access. Specifically:
#     - Detect “Allow” statements with wildcard principals ("*")
#     - Identify read-level permissions granted broadly
#     - Check ACL grants to global public groups (AllUsers, AuthenticatedUsers)
#
#   These checks are intentionally simple and use straightforward logic to
#   minimize false positives while keeping the code easy to read.

"""
Helpers to inspect S3 bucket policies and ACLs for public exposure.

We detect:
- Wildcard principals ("*") in Allow statements
- Read-style permissions granted broadly
- ACL grants to global groups (AllUsers / AuthenticatedUsers)
"""

from typing import Tuple, List, Dict, Any

# S3 ACL "public" group URIs (not "*" like policies; ACLs use group URIs)
ALL_USERS_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",           # anyone on the internet
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers", # any AWS principal
}


# ---------- Policy checks ----------

def policy_allows_public_read(policy: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Return (is_public, reasons).
    True if any Allow statement uses a wildcard principal and read-style actions.
    Read actions considered: GetObject, GetObjectVersion, ListBucket.
    """
    if not policy or "Statement" not in policy:
        return False, []

    reasons: List[str] = []
    is_public = False

    statements = policy["Statement"]
    if isinstance(statements, dict):  # policies can be a single object
        statements = [statements]

    for statement in statements:
        if str(statement.get("Effect", "")).lower() != "allow":
            continue

        # Principal is public if "*" appears anywhere
        principal = statement.get("Principal")
        principal_is_public = False
        if principal == "*" or principal == ["*"]:
            principal_is_public = True
        elif isinstance(principal, dict):
            for value in principal.values():
                if value == "*" or (isinstance(value, list) and "*" in value):
                    principal_is_public = True

        if not principal_is_public:
            continue

        # Action can be string or list
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        read_actions = {"s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket"}
        if any(action in read_actions or action == "s3:*" for action in actions):
            is_public = True
            reasons.append("policy allows read to *")

    return is_public, reasons


def policy_has_wildcard_principal(policy: Dict[str, Any]) -> bool:
    """
    True if any Allow statement uses a wildcard principal, regardless of action.
    """
    if not policy or "Statement" not in policy:
        return False

    statements = policy["Statement"]
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if str(statement.get("Effect", "")).lower() != "allow":
            continue
        principal = statement.get("Principal")
        if principal == "*" or principal == ["*"]:
            return True
        if isinstance(principal, dict):
            for value in principal.values():
                if value == "*" or (isinstance(value, list) and "*" in value):
                    return True
    return False


# ---------- ACL checks ----------

def acl_has_public_grant(acl: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Return (is_public, reasons).
    True if the ACL grants any permission to the global public groups.
    """
    if not acl or "Grants" not in acl:
        return False, []

    is_public = False
    reasons: List[str] = []

    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {}) or {}
        uri = grantee.get("URI")
        if not uri or uri not in ALL_USERS_URIS:
            continue

        perm = grant.get("Permission", "UNKNOWN")
        is_public = True
        reasons.append(f"acl {perm} to {uri.split('/')[-1]}")

    return is_public, reasons
