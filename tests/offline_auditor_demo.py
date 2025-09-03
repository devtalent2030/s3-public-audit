# tests/offline_auditor_demo.py
# Runs auditor.main() with a fake S3 client so no AWS calls are made.

import sys
from src import auditor  # import from src package

# --- Fake S3 responses for three buckets ---

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

PAB_STRICT = {
    "PublicAccessBlockConfiguration": {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
}

PAB_LOOSE = {
    "PublicAccessBlockConfiguration": {
        "BlockPublicAcls": False,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False,
    }
}

def raise_fake(code):
    from botocore.exceptions import ClientError
    raise ClientError({"Error": {"Code": code, "Message": code}}, "FakeOp")

class FakeS3:
    def list_buckets(self):
        return {"Buckets": [{"Name": "example-safe"}, {"Name": "example-risky"}, {"Name": "example-public-acl"}]}

    def get_bucket_location(self, Bucket):
        return {"LocationConstraint": "us-east-1"}

    def get_public_access_block(self, Bucket):
        if Bucket == "example-safe":
            return PAB_STRICT
        return PAB_LOOSE

    def get_bucket_policy(self, Bucket):
        if Bucket == "example-risky":
            return {"Policy": __import__("json").dumps(RISKY_POLICY)}
        if Bucket == "example-safe":
            return {"Policy": __import__("json").dumps(SAFE_POLICY)}
        raise_fake("NoSuchBucketPolicy")

    def get_bucket_acl(self, Bucket):
        if Bucket == "example-public-acl":
            return PUBLIC_ACL
        return PRIVATE_ACL

class FakeSession:
    def client(self, name, region_name=None):
        return FakeS3()

# monkeypatch auditor to use our fake session/client
auditor.get_session = lambda profile=None: FakeSession()
auditor.s3_client = lambda session, region=None: session.client("s3", region_name=region)

def main():
    # emulate CLI: write to a separate file so it doesn't overwrite real runs
    sys.argv = ["auditor.py", "--out", "s3_audit_report_offline.csv", "--log", "INFO", "--json"]
    auditor.main()

if __name__ == "__main__":
    main()
