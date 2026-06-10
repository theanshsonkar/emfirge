"""
S3 report storage.

Persists full JSON scan reports to S3 and generates time-limited presigned
URLs for download. Reports are partitioned by date:
  reports/{YYYY-MM-DD}/analysis-{id}.json
"""

import boto3
import json
import os
from datetime import datetime


def save_report(analysis_id: str, report_data: dict) -> str:
    """Upload a scan report to S3 and return the object key."""
    bucket_name = os.getenv('S3_BUCKET_NAME')
    aws_key = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret = os.getenv('AWS_SECRET_ACCESS_KEY')
    region = os.getenv('AWS_REGION', 'ap-south-1')

    # Create S3 client
    s3 = boto3.client(
        's3',
        aws_access_key_id=aws_key,
        aws_secret_access_key=aws_secret,
        region_name=region
    )

    # Create file path like: reports/2026-03-06/analysis-abc123.json
    date_str = datetime.utcnow().strftime('%Y-%m-%d')
    s3_key = f'reports/{date_str}/analysis-{analysis_id}.json'

    # Convert report data to JSON and upload to S3
    s3.put_object(
        Bucket=bucket_name,
        Key=s3_key,
        Body=json.dumps(report_data, indent=2, default=str),
        ContentType='application/json'
    )
    print(f'Report saved to S3: {s3_key}')
    return s3_key

def get_report_url(s3_key: str) -> str:
    """Generate a presigned URL (1-hour TTL) for downloading a report."""
    bucket_name = os.getenv('S3_BUCKET_NAME')
    aws_key = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret = os.getenv('AWS_SECRET_ACCESS_KEY')
    region = os.getenv('AWS_REGION', 'ap-south-1')

    if not s3_key:
        return ''

    s3 = boto3.client(
        's3',
        aws_access_key_id=aws_key,
        aws_secret_access_key=aws_secret,
        region_name=region
    )

    # presigned URL = temporary link that expires after set time
    url = s3.generate_presigned_url(
        'get_object',
        Params={'Bucket': bucket_name, 'Key': s3_key},
        ExpiresIn=3600  # 1 hour in seconds
    )
    return url