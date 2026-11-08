"""Upload the read-only role template to S3 when the copy there differs from the one in this image.

`emfirge connect` points the CloudFormation quick-create link at
s3://$S3_BUCKET_NAME/cloudformation/iam-role.yaml. Nothing updated that copy on deploy, so new
read actions (Scheduler, CloudFront) reached the repo but not new users. The deploy runs this once
after the engine starts. The template is public and holds no customer data.

Run in the engine image: python scripts/sync_role_template.py [path]
Exit 0 when the copy is current or was updated; exit 1 (deploy warns, does not fail) on any error.
"""
import hashlib
import os
import sys
from pathlib import Path

KEY = "cloudformation/iam-role.yaml"


def sync(path: Path, s3, bucket: str) -> str:
    body = path.read_bytes()
    local_md5 = hashlib.md5(body).hexdigest()  # noqa: S324 - compared with the S3 ETag, not for security
    try:
        remote = s3.head_object(Bucket=bucket, Key=KEY).get("ETag", "").strip('"')
    except Exception:  # noqa: BLE001 - missing object or no permission to read: upload decides
        remote = ""
    if remote == local_md5:
        return "current"
    s3.put_object(Bucket=bucket, Key=KEY, Body=body, ContentType="application/x-yaml", CacheControl="no-cache")
    return "updated"


def main() -> int:
    import boto3
    path = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "cloudformation" / "iam-role.yaml")
    bucket = os.getenv("S3_BUCKET_NAME")
    if not bucket:
        print("role template: S3_BUCKET_NAME is not set; skipped")
        return 1
    s3 = boto3.client("s3", region_name=os.getenv("AWS_REGION", "ap-south-1"))
    try:
        print(f"role template: {sync(path, s3, bucket)}")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"role template: upload failed ({type(exc).__name__})")
        return 1


if __name__ == "__main__":
    sys.exit(main())
