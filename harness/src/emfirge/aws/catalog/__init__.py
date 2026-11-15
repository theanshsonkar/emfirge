"""The Catalog port for AWS, compiled from AWS's published lists (botocore models, the Service Authorization
Reference, CloudFormation schemas). No hand-written code per service; per-service data only in aws/data/overrides.json.

Build:  python -m emfirge.aws.catalog.compile --svcref DIR --cfn DIR --out src/emfirge/aws/data/catalog.json.gz
"""
from .catalog import AwsCatalog
from .store import ResourceTypeInfo

__all__ = ['AwsCatalog', 'ResourceTypeInfo']
