"""
Graph module for building infrastructure relationship graphs.

Transforms collected AWS infrastructure data into a graph representation
with nodes (resources) and edges (relationships between resources).
"""

import re
from typing import Dict, List, Any, Optional, Set
from app.models import AWSInfrastructure


class Graph:
    """
    Graph data structure for AWS infrastructure relationships.
    
    Provides query methods to traverse and analyze the infrastructure graph.
    """
    
    def __init__(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]):
        """
        Initialize the graph with nodes and edges.
        
        Args:
            nodes: List of node dictionaries with 'id', 'type', 'label', 'metadata'
            edges: List of edge dictionaries with 'from', 'to', 'relationship'
        """
        self.nodes = nodes
        self.edges = edges
        
        # Build lookup indexes for efficient queries
        self._node_index = {node['id']: node for node in nodes}
        self._edges_by_source = {}  # from_id -> list of edges
        self._edges_by_target = {}  # to_id -> list of edges
        self._nodes_by_type = {}    # type -> list of nodes
        
        # Populate indexes
        for edge in edges:
            from_id = edge['from']
            to_id = edge['to']
            
            if from_id not in self._edges_by_source:
                self._edges_by_source[from_id] = []
            self._edges_by_source[from_id].append(edge)
            
            if to_id not in self._edges_by_target:
                self._edges_by_target[to_id] = []
            self._edges_by_target[to_id].append(edge)
        
        for node in nodes:
            node_type = node['type']
            if node_type not in self._nodes_by_type:
                self._nodes_by_type[node_type] = []
            self._nodes_by_type[node_type].append(node)
    
    def get_neighbors(self, node_id: str, relationship_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Find all nodes connected to the given node (both inbound and outbound).
        
        Args:
            node_id: ID of the node to find neighbors for
            relationship_type: Optional filter by relationship type
        
        Returns:
            List of neighbor nodes
        """
        neighbors = []
        neighbor_ids = set()
        
        # Get outbound neighbors
        for edge in self._edges_by_source.get(node_id, []):
            if relationship_type is None or edge['relationship'] == relationship_type:
                target_id = edge['to']
                if target_id not in neighbor_ids and target_id in self._node_index:
                    neighbors.append(self._node_index[target_id])
                    neighbor_ids.add(target_id)
        
        # Get inbound neighbors
        for edge in self._edges_by_target.get(node_id, []):
            if relationship_type is None or edge['relationship'] == relationship_type:
                source_id = edge['from']
                if source_id not in neighbor_ids and source_id in self._node_index:
                    neighbors.append(self._node_index[source_id])
                    neighbor_ids.add(source_id)
        
        return neighbors
    
    def get_inbound(self, node_id: str, relationship_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Find all nodes that point TO this node (inbound edges).
        
        Args:
            node_id: ID of the target node
            relationship_type: Optional filter by relationship type
        
        Returns:
            List of source nodes that point to this node
        """
        inbound_nodes = []
        
        for edge in self._edges_by_target.get(node_id, []):
            if relationship_type is None or edge['relationship'] == relationship_type:
                source_id = edge['from']
                if source_id in self._node_index:
                    inbound_nodes.append(self._node_index[source_id])
        
        return inbound_nodes
    
    def get_outbound(self, node_id: str, relationship_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Find all nodes that this node points TO (outbound edges).
        
        Args:
            node_id: ID of the source node
            relationship_type: Optional filter by relationship type
        
        Returns:
            List of target nodes that this node points to
        """
        outbound_nodes = []
        
        for edge in self._edges_by_source.get(node_id, []):
            if relationship_type is None or edge['relationship'] == relationship_type:
                target_id = edge['to']
                if target_id in self._node_index:
                    outbound_nodes.append(self._node_index[target_id])
        
        return outbound_nodes
    
    def find_nodes_by_type(self, node_type: str) -> List[Dict[str, Any]]:
        """
        Find all nodes of a specific type.
        
        Args:
            node_type: Type of nodes to find (e.g., 'ec2_instance', 's3_bucket')
        
        Returns:
            List of nodes matching the type
        """
        return self._nodes_by_type.get(node_type, [])
    
    def has_connection(self, from_id: str, to_id: str, relationship: Optional[str] = None) -> bool:
        """
        Check if an edge exists between two nodes.
        
        Args:
            from_id: Source node ID
            to_id: Target node ID
            relationship: Optional specific relationship type to check
        
        Returns:
            True if the connection exists, False otherwise
        """
        for edge in self._edges_by_source.get(from_id, []):
            if edge['to'] == to_id:
                if relationship is None or edge['relationship'] == relationship:
                    return True
        
        return False
    
    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a node by its ID.
        
        Args:
            node_id: ID of the node to retrieve
        
        Returns:
            Node dictionary or None if not found
        """
        return self._node_index.get(node_id)
    
    def to_dict(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Convert the graph to a dictionary representation.
        
        Returns:
            Dictionary with 'nodes' and 'edges' lists
        """
        return {
            'nodes': self.nodes,
            'edges': self.edges
        }


def _match_arn_to_node_id(arn: str, node_id_set: Set[str]) -> Optional[str]:
    """
    Match a policy Resource ARN to an existing graph node ID.

    Handles S3, RDS, Lambda, and Secrets Manager ARN formats.
    Returns None if no match found (cross-account, non-existent resource, or wildcard).
    """
    if not arn or arn == '*':
        return None

    # S3: arn:aws:s3:::bucket-name or arn:aws:s3:::bucket-name/*
    if ':s3:::' in arn:
        bucket = arn.split(':s3:::')[1].split('/')[0]
        if bucket == '*':
            return None
        if bucket in node_id_set:
            return bucket
        return None

    # RDS: arn:aws:rds:REGION:ACCOUNT:db:INSTANCE-ID
    if ':rds:' in arn and ':db:' in arn:
        rds_id = arn.split(':db:')[-1]
        if rds_id in node_id_set:
            return rds_id
        return None

    # Lambda: arn:aws:lambda:REGION:ACCOUNT:function:NAME
    if ':lambda:' in arn and ':function:' in arn:
        func_name = arn.split(':function:')[-1].split(':')[0]
        if func_name in node_id_set:
            return func_name
        return None

    # Secrets Manager: arn:aws:secretsmanager:REGION:ACCOUNT:secret:NAME-SUFFIX
    if ':secretsmanager:' in arn and ':secret:' in arn:
        secret_raw = arn.split(':secret:')[-1]
        # AWS appends a 6-char random suffix after a hyphen; try both with and without
        if secret_raw in node_id_set:
            return secret_raw
        # Strip last -XXXXXX suffix (6 random chars)
        stripped = re.sub(r'-[A-Za-z0-9]{6}$', '', secret_raw)
        if stripped in node_id_set:
            return stripped
        return None

    # DynamoDB: arn:aws:dynamodb:REGION:ACCOUNT:table/TABLE-NAME
    if ':dynamodb:' in arn and ':table/' in arn:
        table_name = arn.split(':table/')[-1].split('/')[0]
        if table_name in node_id_set:
            return table_name
        return None

    # SQS: arn:aws:sqs:REGION:ACCOUNT:QUEUE-NAME
    if ':sqs:' in arn:
        queue_name = arn.split(':')[-1]
        if queue_name in node_id_set:
            return queue_name
        return None

    return None


def _match_wildcard_arn_to_service(arn: str) -> Optional[str]:
    """
    Determine which service a wildcard Resource ARN targets.

    Returns the node type string if the ARN uses a wildcard pattern for a
    supported service, or None otherwise.
    """
    if not arn or arn == '*':
        return None
    # S3 with wildcard in bucket name: arn:aws:s3:::prod-* or arn:aws:s3:::*
    if ':s3:::' in arn:
        bucket_part = arn.split(':s3:::')[1].split('/')[0]
        if '*' in bucket_part:
            return 's3_bucket'
    # RDS with wildcard: arn:aws:rds:...:db:*
    if ':rds:' in arn and ':db:' in arn:
        rds_part = arn.split(':db:')[-1]
        if '*' in rds_part:
            return 'rds_instance'
    # DynamoDB with wildcard: arn:aws:dynamodb:...:table/*
    if ':dynamodb:' in arn and ':table/' in arn:
        table_part = arn.split(':table/')[-1].split('/')[0]
        if '*' in table_part:
            return 'dynamodb_table'
    # SQS with wildcard: arn:aws:sqs:...:*
    if ':sqs:' in arn:
        queue_part = arn.split(':')[-1]
        if '*' in queue_part:
            return 'sqs_queue'
    return None


def build_graph(infrastructure: AWSInfrastructure) -> Graph:
    """
    Build a graph representation of AWS infrastructure from collected data.
    
    Focuses on EC2, S3, RDS, Lambda, and VPC services.
    
    Args:
        infrastructure: AWSInfrastructure object with collected relationship data
    
    Returns:
        Graph object with nodes and edges, providing query methods for traversal
    """
    nodes = []
    edges = []
    
    # -- EC2 NODES -------------------------------------------------
    # EC2 Instances
    for instance in infrastructure.ec2.instances:
        # Handle both dict and Pydantic model formats
        if isinstance(instance, dict):
            instance_id = instance['id']
            instance_type = instance['type']
            instance_state = instance['state']
            sg_ids = instance.get('sg_ids', [])
            subnet_id = instance.get('subnet_id')
        else:
            instance_id = instance.id
            instance_type = instance.type
            instance_state = instance.state
            sg_ids = instance.sg_ids
            subnet_id = instance.subnet_id
        
        nodes.append({
            'id': instance_id,
            'type': 'ec2_instance',
            'label': f"EC2: {instance_id}",
            'metadata': {
                'instance_type': instance_type,
                'state': instance_state,
                'subnet_id': subnet_id
            }
        })
        
        # Edge: Instance -> Security Group
        for sg_id in sg_ids:
            edges.append({
                'from': instance_id,
                'to': sg_id,
                'relationship': 'uses_security_group'
            })
        
        # Edge: Instance -> Subnet
        if subnet_id:
            edges.append({
                'from': instance_id,
                'to': subnet_id,
                'relationship': 'in_subnet'
            })
        
        # Edge: Instance -> IAM Role (via instance profile)
        instance_profile_arn = instance.get('instance_profile_arn') if isinstance(instance, dict) else getattr(instance, 'instance_profile_arn', None)
        if instance_profile_arn:
            profile_name = instance_profile_arn.split('/')[-1]
            role_id = f"iam-role-{profile_name}"
            if not any(n['id'] == role_id for n in nodes):
                nodes.append({
                    'id': role_id,
                    'type': 'iam_role',
                    'label': f"IAM Role: {profile_name}",
                    'metadata': {'arn': instance_profile_arn, 'source': 'instance_profile'}
                })
            edges.append({
                'from': instance_id,
                'to': role_id,
                'relationship': 'uses_iam_role'
            })
    
    # Security Groups
    for sg in infrastructure.ec2.security_groups:
        # Handle both dict and Pydantic model formats
        if isinstance(sg, dict):
            sg_id = sg['id']
            sg_name = sg['name']
            rules = sg.get('rules', [])
            attached_to = sg.get('attached_to', [])
        else:
            sg_id = sg.id
            sg_name = sg.name
            rules = sg.rules
            attached_to = sg.attached_to
        
        nodes.append({
            'id': sg_id,
            'type': 'security_group',
            'label': f"SG: {sg_name}",
            'metadata': {
                'name': sg_name,
                'rules_count': len(rules),
                'rules': rules,
                'attached_instances': attached_to
            }
        })
        
        # Edge: Security Group -> Instance (attached_to)
        for instance_id in attached_to:
            edges.append({
                'from': sg_id,
                'to': instance_id,
                'relationship': 'attached_to_instance'
            })
    
    # -- INTERNET REACHABILITY -------------------------------------
    # Add a virtual INTERNET node and edges for any SG with 0.0.0.0/0 or ::/0 rules
    # Only connect INTERNET to resources that are in PUBLIC subnets
    internet_node_added = False
    
    # Build a lookup: resource_id → is_in_public_subnet
    # A resource is in a public subnet if any subnet containing it has is_public=True
    resource_in_public_subnet = set()
    for subnet in infrastructure.vpc.subnets:
        if isinstance(subnet, dict):
            is_public = subnet.get('is_public', False)
            resources = subnet.get('resources', [])
        else:
            is_public = subnet.is_public
            resources = subnet.resources
        if is_public:
            for res_id in resources:
                resource_in_public_subnet.add(res_id)
    
    # If no subnet data exists at all (empty VPC data), fall back to current behavior:
    # treat all resources as publicly reachable (preserves backward compat)
    has_subnet_data = len(infrastructure.vpc.subnets) > 0

    for sg in infrastructure.ec2.security_groups:
        if isinstance(sg, dict):
            sg_id = sg['id']
            rules = sg.get('rules', [])
            attached_to = sg.get('attached_to', [])
        else:
            sg_id = sg.id
            rules = sg.rules
            attached_to = sg.attached_to

        # Check if any rule allows unrestricted internet access
        is_internet_open = any(
            '0.0.0.0/0' in rule.get('ip_ranges', []) or '::/0' in rule.get('ip_ranges', [])
            for rule in rules
        )

        if is_internet_open:
            # Determine which attached resources are in public subnets
            if has_subnet_data:
                reachable_instances = [
                    iid for iid in attached_to
                    if iid in resource_in_public_subnet
                ]
            else:
                # No subnet data → assume all are reachable (backward compat)
                reachable_instances = attached_to

            # Only create INTERNET edges if at least one attached resource is in a public subnet
            if reachable_instances:
                # Add INTERNET node once
                if not internet_node_added:
                    nodes.append({
                        'id': 'INTERNET',
                        'type': 'internet',
                        'label': 'Internet',
                        'metadata': {'is_virtual': True}
                    })
                    internet_node_added = True

                # Edge: INTERNET -> SG
                edges.append({
                    'from': 'INTERNET',
                    'to': sg_id,
                    'relationship': 'REACHES'
                })

                # Edge: INTERNET -> each reachable instance via this SG
                for instance_id in reachable_instances:
                    edges.append({
                        'from': 'INTERNET',
                        'to': instance_id,
                        'relationship': 'REACHES_VIA_SG'
                    })

    # Load Balancers
    for lb in infrastructure.ec2.load_balancers:
        # Handle both dict and Pydantic model formats
        if isinstance(lb, dict):
            lb_arn = lb['arn']
            lb_type = lb['type']
            target_instances = lb.get('target_instances', [])
        else:
            lb_arn = lb.arn
            lb_type = lb.type
            target_instances = lb.target_instances
        
        lb_id = lb_arn.split('/')[-1]  # Extract short ID from ARN
        nodes.append({
            'id': lb_arn,
            'type': 'load_balancer',
            'label': f"LB: {lb_id}",
            'metadata': {
                'type': lb_type,
                'target_count': len(target_instances)
            }
        })
        
        # Edge: Load Balancer -> EC2 Instance
        for instance_id in target_instances:
            edges.append({
                'from': lb_arn,
                'to': instance_id,
                'relationship': 'targets_instance'
            })
    
    # -- S3 NODES --------------------------------------------------
    for bucket in infrastructure.s3.buckets:
        # Handle both dict and Pydantic model formats
        if isinstance(bucket, dict):
            bucket_name = bucket['name']
            is_public = bucket.get('is_public', False)
            has_cloudfront = bucket.get('has_cloudfront', False)
            policy = bucket.get('policy')
            is_empty = bucket.get('is_empty', False)
        else:
            bucket_name = bucket.name
            is_public = bucket.is_public
            has_cloudfront = bucket.has_cloudfront
            policy = bucket.policy
            is_empty = bucket.is_empty
        
        nodes.append({
            'id': bucket_name,
            'type': 's3_bucket',
            'label': f"S3: {bucket_name}",
            'metadata': {
                'is_public': is_public,
                'has_cloudfront': has_cloudfront,
                'has_policy': policy is not None,
                'is_empty': is_empty
            }
        })
        
        # Edge: S3 Bucket -> CloudFront (if has_cloudfront is True)
        if has_cloudfront:
            # Create a virtual CloudFront node for this bucket
            cf_id = f"cloudfront-{bucket_name}"
            nodes.append({
                'id': cf_id,
                'type': 'cloudfront_distribution',
                'label': f"CloudFront: {bucket_name}",
                'metadata': {
                    'origin_bucket': bucket_name
                }
            })
            edges.append({
                'from': cf_id,
                'to': bucket_name,
                'relationship': 'serves_from_bucket'
            })
    
    # -- RDS NODES -------------------------------------------------
    for rds in infrastructure.rds.rds_instances:
        # Handle both dict and Pydantic model formats
        if isinstance(rds, dict):
            rds_id = rds['id']
            sg_ids = rds.get('sg_ids', [])
            publicly_accessible = rds.get('publicly_accessible', False)
            encrypted = rds.get('encrypted', False)
        else:
            rds_id = rds.id
            sg_ids = rds.sg_ids
            publicly_accessible = rds.publicly_accessible
            encrypted = rds.encrypted
        
        nodes.append({
            'id': rds_id,
            'type': 'rds_instance',
            'label': f"RDS: {rds_id}",
            'metadata': {
                'publicly_accessible': publicly_accessible,
                'encrypted': encrypted,
                'security_groups': sg_ids
            }
        })
        
        # Edge: RDS -> Security Group
        for sg_id in sg_ids:
            edges.append({
                'from': rds_id,
                'to': sg_id,
                'relationship': 'uses_security_group'
            })
    
    # -- LAMBDA NODES ----------------------------------------------
    for func in infrastructure.lambda_data.functions:
        # Handle both dict and Pydantic model formats
        if isinstance(func, dict):
            func_name = func['name']
            role_arn = func.get('role_arn')
            vpc_id = func.get('vpc_id')
            subnet_ids = func.get('subnet_ids', [])
        else:
            func_name = func.name
            role_arn = func.role_arn
            vpc_id = func.vpc_id
            subnet_ids = func.subnet_ids
        
        nodes.append({
            'id': func_name,
            'type': 'lambda_function',
            'label': f"Lambda: {func_name}",
            'metadata': {
                'role_arn': role_arn,
                'vpc_id': vpc_id,
                'subnet_count': len(subnet_ids)
            }
        })
        
        # Edge: Lambda -> IAM Role
        if role_arn:
            role_name = role_arn.split('/')[-1]
            role_id = f"iam-role-{role_name}"
            
            # Create IAM Role node if it doesn't exist
            if not any(n['id'] == role_id for n in nodes):
                nodes.append({
                    'id': role_id,
                    'type': 'iam_role',
                    'label': f"IAM Role: {role_name}",
                    'metadata': {
                        'arn': role_arn
                    }
                })
            
            edges.append({
                'from': func_name,
                'to': role_id,
                'relationship': 'uses_iam_role'
            })
        
        # Edge: Lambda -> VPC
        if vpc_id:
            edges.append({
                'from': func_name,
                'to': vpc_id,
                'relationship': 'in_vpc'
            })
        
        # Edge: Lambda -> Subnet
        for subnet_id in subnet_ids:
            edges.append({
                'from': func_name,
                'to': subnet_id,
                'relationship': 'in_subnet'
            })
        
        # Edge: Lambda -> Secrets (env var refs)
        secret_refs = func.get('secret_refs', []) if isinstance(func, dict) else func.secret_refs
        for secret_id in secret_refs:
            if not any(n['id'] == secret_id for n in nodes):
                nodes.append({
                    'id': secret_id,
                    'type': 'secretsmanager_secret',
                    'label': f"Secret: {secret_id}",
                    'metadata': {'source': 'lambda_env'}
                })
            edges.append({
                'from': func_name,
                'to': secret_id,
                'relationship': 'REFERENCES_SECRET'
            })
    
    # -- ECS NODES -------------------------------------------------
    if infrastructure.ecs.task_role_arns:
        nodes.append({
            'id': 'ecs_tasks',
            'type': 'ecs_tasks',
            'label': 'ECS Tasks',
            'metadata': {'is_virtual': True}
        })
        for role_arn in infrastructure.ecs.task_role_arns:
            role_name = role_arn.split('/')[-1]
            role_id = f"iam-role-{role_name}"
            if not any(n['id'] == role_id for n in nodes):
                nodes.append({
                    'id': role_id,
                    'type': 'iam_role',
                    'label': f"IAM Role: {role_name}",
                    'metadata': {'arn': role_arn, 'source': 'ecs_task'}
                })
            edges.append({
                'from': 'ecs_tasks',
                'to': role_id,
                'relationship': 'USES_ROLE'
            })

    # -- VPC NODES -------------------------------------------------
    for subnet in infrastructure.vpc.subnets:
        # Handle both dict and Pydantic model formats
        if isinstance(subnet, dict):
            subnet_id = subnet['id']
            vpc_id = subnet['vpc_id']
            resources = subnet.get('resources', [])
        else:
            subnet_id = subnet.id
            vpc_id = subnet.vpc_id
            resources = subnet.resources
        
        nodes.append({
            'id': subnet_id,
            'type': 'vpc_subnet',
            'label': f"Subnet: {subnet_id}",
            'metadata': {
                'vpc_id': vpc_id,
                'resource_count': len(resources)
            }
        })
        
        # Edge: Subnet -> VPC
        edges.append({
            'from': subnet_id,
            'to': vpc_id,
            'relationship': 'belongs_to_vpc'
        })
        
        # Edge: Subnet -> Resources (EC2, Lambda, etc.)
        for resource_id in resources:
            edges.append({
                'from': subnet_id,
                'to': resource_id,
                'relationship': 'contains_resource'
            })
    
    # Create VPC nodes from subnets
    vpc_ids = set()
    for subnet in infrastructure.vpc.subnets:
        if isinstance(subnet, dict):
            vpc_ids.add(subnet['vpc_id'])
        else:
            vpc_ids.add(subnet.vpc_id)
    
    for vpc_id in vpc_ids:
        if not any(n['id'] == vpc_id for n in nodes):
            subnet_count = sum(1 for s in infrastructure.vpc.subnets 
                             if (s['vpc_id'] if isinstance(s, dict) else s.vpc_id) == vpc_id)
            nodes.append({
                'id': vpc_id,
                'type': 'vpc',
                'label': f"VPC: {vpc_id}",
                'metadata': {
                    'is_default': vpc_id == infrastructure.vpc.default_vpc_id,
                    'subnet_count': subnet_count
                }
            })
    
    # -- EBS VOLUME NODES ------------------------------------------
    # Unattached volumes (state=available) - no edges, isolated for orphan detection
    for vol in infrastructure.ec2.ebs_volumes:
        vol_id = vol['id'] if isinstance(vol, dict) else vol.id
        size_gb = vol['size_gb'] if isinstance(vol, dict) else vol.size_gb
        volume_type = vol['volume_type'] if isinstance(vol, dict) else vol.volume_type
        az = vol['availability_zone'] if isinstance(vol, dict) else vol.availability_zone
        nodes.append({
            'id': vol_id,
            'type': 'ebs_volume',
            'label': f"EBS: {size_gb}GB",
            'metadata': {
                'size_gb': size_gb,
                'volume_type': volume_type,
                'availability_zone': az,
            }
        })

    # -- ELASTIC IP NODES ------------------------------------------
    # All EIPs - no edges, orphan detection filters by is_attached
    for eip in infrastructure.ec2.elastic_ips:
        alloc_id = eip['allocation_id'] if isinstance(eip, dict) else eip.allocation_id
        public_ip = eip['public_ip'] if isinstance(eip, dict) else eip.public_ip
        is_attached = eip['is_attached'] if isinstance(eip, dict) else eip.is_attached
        nodes.append({
            'id': alloc_id,
            'type': 'elastic_ip',
            'label': f"EIP: {public_ip}",
            'metadata': {
                'public_ip': public_ip,
                'is_attached': is_attached,
            }
        })

    # -- API GATEWAY NODES -----------------------------------------
    for api in infrastructure.api_gateway.apis:
        if isinstance(api, dict):
            api_id = api['id']
            api_name = api['name']
            api_type = api['api_type']
            endpoint_type = api['endpoint_type']
            auth_type = api['auth_type']
            has_waf = api.get('has_waf', False)
        else:
            api_id = api.id
            api_name = api.name
            api_type = api.api_type
            endpoint_type = api.endpoint_type
            auth_type = api.auth_type
            has_waf = api.has_waf

        nodes.append({
            'id': api_id,
            'type': 'api_gateway',
            'label': f"API GW: {api_name}",
            'metadata': {
                'api_type': api_type,
                'endpoint_type': endpoint_type,
                'auth_type': auth_type,
                'has_waf': has_waf,
            }
        })

        # Edge: INTERNET -> api_gateway (if endpoint is public)
        if endpoint_type != 'PRIVATE':
            if not internet_node_added:
                nodes.append({
                    'id': 'INTERNET',
                    'type': 'internet',
                    'label': 'Internet',
                    'metadata': {'is_virtual': True}
                })
                internet_node_added = True
            edges.append({
                'from': 'INTERNET',
                'to': api_id,
                'relationship': 'REACHES'
            })

    # -- ELASTICACHE NODES -----------------------------------------
    for cluster in infrastructure.elasticache.clusters:
        if isinstance(cluster, dict):
            cluster_id = cluster['id']
            engine = cluster['engine']
            node_type_val = cluster['node_type']
            sg_ids = cluster.get('sg_ids', [])
            vpc_id = cluster.get('vpc_id')
        else:
            cluster_id = cluster.id
            engine = cluster.engine
            node_type_val = cluster.node_type
            sg_ids = cluster.sg_ids
            vpc_id = cluster.vpc_id

        nodes.append({
            'id': cluster_id,
            'type': 'elasticache_cluster',
            'label': f"ElastiCache: {cluster_id}",
            'metadata': {
                'engine': engine,
                'node_type': node_type_val,
                'vpc_id': vpc_id,
            }
        })

        # Edge: elasticache_cluster -> security_group
        for sg_id in sg_ids:
            edges.append({
                'from': cluster_id,
                'to': sg_id,
                'relationship': 'uses_security_group'
            })

    # -- SQS NODES ------------------------------------------------
    for queue in infrastructure.sqs.queues:
        if isinstance(queue, dict):
            queue_name = queue['name']
            queue_arn = queue['arn']
            encrypted = queue.get('encrypted', False)
            is_public = queue.get('is_public', False)
        else:
            queue_name = queue.name
            queue_arn = queue.arn
            encrypted = queue.encrypted
            is_public = queue.is_public

        nodes.append({
            'id': queue_name,
            'type': 'sqs_queue',
            'label': f"SQS: {queue_name}",
            'metadata': {
                'arn': queue_arn,
                'encrypted': encrypted,
                'is_public': is_public,
            }
        })

    # -- DYNAMODB NODES --------------------------------------------
    for table in infrastructure.dynamodb.tables:
        if isinstance(table, dict):
            table_name = table['name']
            table_arn = table['arn']
            encryption_type = table.get('encryption_type', 'DEFAULT')
            pitr_enabled = table.get('pitr_enabled', False)
            billing_mode = table.get('billing_mode', 'PROVISIONED')
        else:
            table_name = table.name
            table_arn = table.arn
            encryption_type = table.encryption_type
            pitr_enabled = table.pitr_enabled
            billing_mode = table.billing_mode

        nodes.append({
            'id': table_name,
            'type': 'dynamodb_table',
            'label': f"DynamoDB: {table_name}",
            'metadata': {
                'arn': table_arn,
                'encryption_type': encryption_type,
                'pitr_enabled': pitr_enabled,
                'billing_mode': billing_mode,
            }
        })

    # -- IAM POLICY EDGES (can_access) --------------------------------
    # Create edges from IAM roles to data stores based on parsed policy documents.
    # This enables BFS to trace full attack paths: EC2 → Role → S3/RDS.
    node_id_set = {n['id'] for n in nodes}
    MAX_EDGES_PER_ROLE = 50  # cap to prevent graph explosion from overprivileged roles

    for role_policy in infrastructure.iam.role_policies:
        role_name = role_policy.role_name if not isinstance(role_policy, dict) else role_policy['role_name']
        role_arn = role_policy.role_arn if not isinstance(role_policy, dict) else role_policy['role_arn']
        has_admin = role_policy.has_admin if not isinstance(role_policy, dict) else role_policy.get('has_admin', False)
        accessible_resources = role_policy.accessible_resources if not isinstance(role_policy, dict) else role_policy.get('accessible_resources', [])
        policy_names = role_policy.policy_names if not isinstance(role_policy, dict) else role_policy.get('policy_names', [])

        role_id = f"iam-role-{role_name}"

        # Create role node if it doesn't exist yet (role not used by any Lambda/ECS/EC2)
        if role_id not in node_id_set:
            nodes.append({
                'id': role_id,
                'type': 'iam_role',
                'label': f"IAM Role: {role_name}",
                'metadata': {'arn': role_arn, 'has_admin': has_admin, 'policies': policy_names}
            })
            node_id_set.add(role_id)

        edge_count = 0

        if has_admin:
            # Admin role can access ALL data stores - create edges to each
            for n in nodes:
                if n['type'] in ('s3_bucket', 'rds_instance', 'secretsmanager_secret', 'dynamodb_table', 'sqs_queue') and edge_count < MAX_EDGES_PER_ROLE:
                    edges.append({'from': role_id, 'to': n['id'], 'relationship': 'can_access'})
                    edge_count += 1
        else:
            for arn in accessible_resources:
                if edge_count >= MAX_EDGES_PER_ROLE:
                    break
                if arn == '*':
                    # Wildcard resource - treat as admin for data stores
                    for n in nodes:
                        if n['type'] in ('s3_bucket', 'rds_instance', 'secretsmanager_secret', 'dynamodb_table', 'sqs_queue') and edge_count < MAX_EDGES_PER_ROLE:
                            edges.append({'from': role_id, 'to': n['id'], 'relationship': 'can_access'})
                            edge_count += 1
                    break
                # Try exact match
                target_id = _match_arn_to_node_id(arn, node_id_set)
                if target_id:
                    edges.append({'from': role_id, 'to': target_id, 'relationship': 'can_access'})
                    edge_count += 1
                else:
                    # Try wildcard pattern match (e.g., arn:aws:s3:::prod-*)
                    service_type = _match_wildcard_arn_to_service(arn)
                    if service_type:
                        # Extract prefix pattern for matching
                        if ':s3:::' in arn:
                            pattern = arn.split(':s3:::')[1].split('/')[0]
                        else:
                            pattern = None
                        if pattern and '*' in pattern:
                            prefix = pattern.replace('*', '')
                            for n in nodes:
                                if n['type'] == service_type and n['id'].startswith(prefix) and edge_count < MAX_EDGES_PER_ROLE:
                                    edges.append({'from': role_id, 'to': n['id'], 'relationship': 'can_access'})
                                    edge_count += 1

    return Graph(nodes=nodes, edges=edges)


SLICE_CATEGORIES = {
    'scale_traffic':  ['ec2_instance', 'rds_instance', 'lambda_function', 'load_balancer', 'elasticache_cluster', 'api_gateway', 'sqs_queue'],
    'attack_surface': ['internet', 'security_group', 'ec2_instance', 'api_gateway'],
    'data_exposure':  ['s3_bucket', 'rds_instance', 'secretsmanager_secret', 'iam_role', 'dynamodb_table', 'sqs_queue'],
    'general':        None,
}


# Edge weights for Dijkstra - lower = easier to exploit.
# Scale: 0 = metadata (no exploit step), 1 = trivial, 2 = easy, 3 = medium,
#         4 = hard, 5 = very hard (cross-boundary).
EDGE_WEIGHTS: Dict[str, int] = {
    'REACHES': 1,              # Internet → SG: trivial, automated scanners
    'REACHES_VIA_SG': 1,       # Internet → instance: direct exposure
    'attached_to_instance': 0, # SG → instance: implicit, not an exploit step
    'targets_instance': 2,     # LB → instance: need to bypass LB
    'uses_iam_role': 3,        # Instance → role: need shell + credential theft
    'can_access': 2,           # Role → data store: have creds, call API
    'uses_security_group': 0,  # Instance → SG: metadata relationship
    'in_subnet': 0,            # Resource → subnet: metadata
    'contains_resource': 0,    # Subnet → resource: metadata
    'belongs_to_vpc': 0,       # Subnet → VPC: metadata
    'serves_from_bucket': 1,   # CloudFront → S3: CDN origin access
    'REFERENCES_SECRET': 2,    # Lambda → secret: need function access
    'USES_ROLE': 3,            # ECS → role: need container access
    'in_vpc': 0,               # Lambda → VPC: metadata
}


def dijkstra_from_internet(graph: Graph) -> Dict[str, Dict[str, Any]]:
    """
    Dijkstra's algorithm from INTERNET node — finds lowest-cost (easiest exploit)
    paths to all reachable resources.

    Unlike BFS which counts hops, this weights edges by exploit difficulty.
    A path with 5 hops but all trivial edges (cost=5) is MORE dangerous than
    a path with 2 hops requiring credential theft (cost=6).

    Args:
        graph: Infrastructure graph with INTERNET node

    Returns:
        Dict mapping node_id -> {distance: int, previous: str|None}
        distance = total exploit cost from INTERNET (lower = easier to attack)
        previous = previous node on the easiest path (for path reconstruction)
        Returns empty dict if no INTERNET node exists.
    """
    import heapq

    if 'INTERNET' not in graph._node_index:
        return {}

    distances: Dict[str, int] = {'INTERNET': 0}
    previous: Dict[str, Optional[str]] = {'INTERNET': None}
    visited: Set[str] = set()
    heap = [(0, 'INTERNET')]  # (cost, node_id)

    while heap:
        cost, node_id = heapq.heappop(heap)

        if node_id in visited:
            continue
        visited.add(node_id)

        for edge in graph._edges_by_source.get(node_id, []):
            neighbor = edge['to']
            if neighbor in visited:
                continue

            edge_type = edge['relationship']
            weight = EDGE_WEIGHTS.get(edge_type, 3)  # default: medium difficulty

            new_cost = cost + weight

            if neighbor not in distances or new_cost < distances[neighbor]:
                distances[neighbor] = new_cost
                previous[neighbor] = node_id
                heapq.heappush(heap, (new_cost, neighbor))

    # Build result dict (exclude INTERNET itself)
    result: Dict[str, Dict[str, Any]] = {}
    for nid in distances:
        if nid == 'INTERNET':
            continue
        result[nid] = {
            'distance': distances[nid],
            'previous': previous.get(nid),
        }

    return result


def betweenness_centrality(graph: Graph, source_nodes: Optional[List[str]] = None) -> Dict[str, float]:
    """
    Calculate betweenness centrality for all nodes in the graph.

    Betweenness centrality measures how often a node appears on shortest paths
    between other nodes. High centrality = chokepoint. Hardening a high-centrality
    node eliminates the most attack paths simultaneously.

    Uses Brandes' algorithm (O(V*E)), efficient for graphs under 10K nodes.

    Args:
        graph: Infrastructure graph
        source_nodes: Optional list of source node IDs to compute from.
                      If None, uses INTERNET + all internet-reachable nodes.
                      Limiting sources keeps computation focused on attack-relevant paths.

    Returns:
        Dict mapping node_id -> centrality score (float, normalized).
        Higher = more shortest paths pass through this node.
        Returns empty dict if graph has fewer than 3 nodes.
    """
    from collections import deque

    all_node_ids = list(graph._node_index.keys())
    if len(all_node_ids) < 3:
        return {}

    # Initialize centrality scores
    centrality: Dict[str, float] = {nid: 0.0 for nid in all_node_ids}

    # Determine source nodes for BFS
    if source_nodes is None:
        if 'INTERNET' in graph._node_index:
            reachable = get_internet_reachable_set(graph)
            sources = ['INTERNET'] + [nid for nid in reachable if nid != 'INTERNET']
        else:
            sources = all_node_ids
    else:
        sources = source_nodes

    # Brandes' algorithm - BFS from each source, accumulate dependency
    for s in sources:
        stack: List[str] = []
        predecessors: Dict[str, List[str]] = {nid: [] for nid in all_node_ids}
        sigma: Dict[str, int] = {nid: 0 for nid in all_node_ids}
        sigma[s] = 1
        dist: Dict[str, int] = {nid: -1 for nid in all_node_ids}
        dist[s] = 0
        queue = deque([s])

        while queue:
            v = queue.popleft()
            stack.append(v)
            for edge in graph._edges_by_source.get(v, []):
                w = edge['to']
                if w not in graph._node_index:
                    continue
                if dist[w] < 0:
                    dist[w] = dist[v] + 1
                    queue.append(w)
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    predecessors[w].append(v)

        # Back-propagation of dependencies
        delta: Dict[str, float] = {nid: 0.0 for nid in all_node_ids}
        while stack:
            w = stack.pop()
            for v in predecessors[w]:
                if sigma[w] > 0:
                    delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
            if w != s:
                centrality[w] += delta[w]

    # Normalize to 0-1 range
    n = len(sources)
    if n > 2:
        norm = 1.0 / ((n - 1) * (n - 2))
        centrality = {nid: round(score * norm, 6) for nid, score in centrality.items()}

    return centrality


def get_internet_reachable_set(graph: Graph) -> set:
    """
    BFS from INTERNET node — returns a flat set of all reachable resource IDs.

    Used by graph-aware rules to determine if a resource is internet-reachable.
    Returns empty set if no INTERNET node exists (conservative: rules won't downgrade).
    """
    if not graph or 'INTERNET' not in graph._node_index:
        return set()

    visited = set()
    queue = ['INTERNET']
    visited.add('INTERNET')

    while queue:
        current = queue.pop(0)
        for edge in graph._edges_by_source.get(current, []):
            neighbor = edge['to']
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)

    visited.discard('INTERNET')
    return visited


def get_attack_path_to(graph: Graph, target_id: str) -> Optional[List[str]]:
    """
    BFS from INTERNET to target — returns shortest path as list of node IDs.

    Used by graph-aware rules to populate the attack_path field on findings.
    Returns None if target is not reachable from INTERNET.

    Args:
        graph: Infrastructure graph with INTERNET node
        target_id: ID of the target resource

    Returns:
        List of node IDs from INTERNET to target (inclusive), or None if unreachable.
    """
    if not graph or 'INTERNET' not in graph._node_index:
        return None
    if target_id not in graph._node_index:
        return None

    visited = set()
    queue = [('INTERNET', ['INTERNET'])]
    visited.add('INTERNET')

    while queue:
        current, path = queue.pop(0)
        for edge in graph._edges_by_source.get(current, []):
            neighbor = edge['to']
            if neighbor == target_id:
                return path + [neighbor]
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, path + [neighbor]))

    return None


def bfs_from_internet(graph: Graph) -> dict:
    """
    BFS traversal from the INTERNET node to find all reachable resources.

    Returns nodes in BFS order with their depth (distance from internet),
    plus all edges between reachable nodes.

    Args:
        graph: Full infrastructure graph

    Returns:
        Dict with 'nodes', 'edges', 'category', 'layers' keys.
        'layers' maps node_id -> BFS depth (0 = INTERNET itself).
        Returns empty result if no INTERNET node exists.
    """
    if 'INTERNET' not in graph._node_index:
        return {'nodes': [], 'edges': [], 'category': 'attack_surface', 'layers': {}}

    visited = set()
    queue = ['INTERNET']
    layers = {'INTERNET': 0}
    visited.add('INTERNET')

    while queue:
        current = queue.pop(0)
        depth = layers[current]
        for edge in graph._edges_by_source.get(current, []):
            neighbor = edge['to']
            if neighbor not in visited:
                visited.add(neighbor)
                layers[neighbor] = depth + 1
                queue.append(neighbor)

    edges = []
    for nid in visited:
        for edge in graph._edges_by_source.get(nid, []):
            if edge['to'] in visited:
                edges.append(edge)

    return {
        'nodes': [graph._node_index[nid] for nid in visited if nid in graph._node_index],
        'edges': edges,
        'category': 'attack_surface',
        'layers': layers,
    }


def get_simulation_slice(graph: Graph, category: str) -> dict:
    """
    Return a subgraph relevant to the given simulation category.

    For 'attack_surface' and 'general', uses real BFS traversal from the INTERNET
    node so the slice reflects actual reachability, not just node type filtering.
    Falls back to type-based filtering if no INTERNET node exists.

    Args:
        graph: Full infrastructure graph
        category: One of 'scale_traffic', 'attack_surface', 'data_exposure', 'cost', 'general'

    Returns:
        Dict with 'nodes', 'edges', 'category', and 'layers' keys.
        'layers' maps node_id -> BFS depth (only populated for BFS-based slices).
    """
    if category in ('attack_surface', 'general', 'recommendations'):
        result = bfs_from_internet(graph)
        if result['nodes']:
            return result
        # fallback: no INTERNET node - return first 50 nodes
        node_ids = set(list(graph._node_index.keys())[:50])
    elif category == 'data_exposure':
        # BFS first - return data-type nodes reachable from internet
        DATA_TYPES = {'s3_bucket', 'rds_instance', 'secretsmanager_secret', 'iam_role'}
        bfs_result = bfs_from_internet(graph)
        bfs_ids = {n['id'] for n in bfs_result['nodes']}
        bfs_layers = bfs_result.get('layers', {})
        data_node_ids = set()
        for t in DATA_TYPES:
            for n in graph.find_nodes_by_type(t):
                data_node_ids.add(n['id'])
        reachable_data_ids = data_node_ids & bfs_ids

        # If no data nodes are BFS-reachable, fall back to ALL data nodes.
        # S3 buckets and RDS have no direct internet edge in the graph so the
        # BFS intersection is always empty - returning empty gives Claude nothing
        # to reason about and produces "empty infrastructure graph" errors.
        if reachable_data_ids:
            node_ids = reachable_data_ids
            layers = {nid: bfs_layers[nid] for nid in node_ids if nid in bfs_layers}
        else:
            node_ids = data_node_ids
            layers = {}

        if not node_ids:
            return {'nodes': [], 'edges': [], 'category': category, 'layers': {}}

        edges = []
        for nid in node_ids:
            for edge in graph._edges_by_source.get(nid, []):
                if edge['to'] in node_ids:
                    edges.append(edge)

        return {
            'nodes': [graph._node_index[nid] for nid in node_ids if nid in graph._node_index],
            'edges': edges,
            'category': category,
            'layers': layers,
        }
    else:
        node_types = SLICE_CATEGORIES.get(category, None)
        node_ids = set()
        if node_types:
            for t in node_types:
                for n in graph.find_nodes_by_type(t):
                    node_ids.add(n['id'])
        else:
            node_ids = set(list(graph._node_index.keys())[:50])

    edges = []
    for nid in node_ids:
        for edge in graph._edges_by_source.get(nid, []):
            if edge['to'] in node_ids:
                edges.append(edge)

    return {
        'nodes': [graph._node_index[nid] for nid in node_ids if nid in graph._node_index],
        'edges': edges,
        'category': category,
        'layers': {},
    }


def validate_simulation_response(response: dict, graph: Graph) -> dict:
    """
    Strip any node IDs from a simulation response that no longer exist in the graph.

    Ensures LLM-generated stage node_ids and recommendation affected_node_ids
    only reference real nodes, preventing downstream KeyErrors.

    Args:
        response: Simulation response dict with 'stages' and 'recommendations' keys
        graph: Infrastructure graph to validate against

    Returns:
        Cleaned response dict (mutates in place and returns)
    """
    for stage in response.get('stages', []):
        stage['node_ids'] = [nid for nid in stage.get('node_ids', []) if graph.get_node(nid)]
    for rec in response.get('recommendations', []):
        rec['affected_node_ids'] = [nid for nid in rec.get('affected_node_ids', []) if graph.get_node(nid)]
    return response


def classify_query(query: str) -> str:
    """
    Classify a simulation query into one of four categories based on keywords.

    Args:
        query: Free-text user query

    Returns:
        Category string: 'scale_traffic' | 'attack_surface' | 'data_exposure' | 'cost' | 'general'
    """
    q = query.lower()
    if any(w in q for w in ['user', 'traffic', 'scale', 'load', 'concurrent', 'request', 'rps', 'handle']):
        return 'scale_traffic'
    if any(w in q for w in ['attack', 'breach', 'hack', 'reach', 'internet', 'exploit', 'attacker', 'compromise', 'steal', 'access']):
        return 'attack_surface'
    if any(w in q for w in ['data', 'bucket', 'database', 'secret', 'leak', 'exposed', 's3', 'rds']):
        return 'data_exposure'
    if any(w in q for w in ['cost', 'bill', 'expensive', 'optimize', 'spend', 'saving']):
        return 'cost'
    recommendations_keywords = [
        'best', 'improve', 'recommend', 'suggest', 'should', 'help', 'advice',
        'fix', 'what can', 'how can', 'priority', 'focus',
    ]
    if any(k in q for k in recommendations_keywords):
        return 'recommendations'
    return 'general'


def format_graph_for_claude(slice_dict: dict) -> str:
    """
    Format a graph slice as a compact text representation for Claude prompts.

    Includes BFS depth on each node when available (depth=N means N hops from internet).
    Only emits metadata fields relevant to security/reliability analysis.

    Args:
        slice_dict: Dict with 'nodes', 'edges', 'category', 'layers' keys

    Returns:
        Multi-line string describing nodes and edges with depth annotations
    """
    layers = slice_dict.get('layers', {})
    lines = [f"INFRASTRUCTURE GRAPH (category: {slice_dict['category']}):", "Nodes:"]
    for n in slice_dict['nodes']:
        meta = {k: v for k, v in n.get('metadata', {}).items()
                if k in ('instance_type', 'state', 'public_ip', 'is_public',
                         'engine', 'multi_az', 'runtime', 'policy_names',
                         'open_ports', 'instance_profile')}
        depth = layers.get(n['id'], '?')
        lines.append(f"  - {n['id']} [{n['type']}] depth={depth} {meta}")
    lines.append("Edges:")
    for e in slice_dict['edges']:
        lines.append(f"  - {e['from']} --{e['relationship']}--> {e['to']}")
    return "\n".join(lines)


def find_orphaned_resources(graph: Graph) -> List[Dict[str, Any]]:
    """
    Find orphaned resources - nodes with zero inbound AND zero outbound edges.
    
    These are resources that exist but have no relationships with other infrastructure,
    indicating they may be unused and costing money unnecessarily.
    
    Special handling for S3 buckets:
    - Skip buckets that are not empty (have stored objects)
    - Skip buckets with production-related names
    - Only flag empty buckets with test/temporary names
    
    Args:
        graph: Infrastructure graph to analyze
    
    Returns:
        List of orphaned resources with type, ID, label, and estimated cost impact
    """
    orphaned = []
    
    # Cost estimates per resource type (monthly USD)
    cost_estimates = {
        'ec2_instance': {'amount': 10.0, 'unit': 'per instance'},
        'rds_instance': {'amount': 25.0, 'unit': 'per instance'},
        's3_bucket': {'amount': 1.0, 'unit': 'per bucket (storage varies)'},
        'lambda_function': {'amount': 0.5, 'unit': 'per function (if unused)'},
        'load_balancer': {'amount': 18.0, 'unit': 'per load balancer'},
        'vpc': {'amount': 0.0, 'unit': 'free (but cleanup recommended)'},
        'vpc_subnet': {'amount': 0.0, 'unit': 'free (but cleanup recommended)'},
        'security_group': {'amount': 0.0, 'unit': 'free (but cleanup recommended)'},
        'iam_role': {'amount': 0.0, 'unit': 'free (but security risk if unused)'},
        'cloudfront_distribution': {'amount': 1.0, 'unit': 'per distribution'},
        'ebs_volume': {'amount': 0.0, 'unit': 'per GB × $0.10/mo'},
        'elastic_ip': {'amount': 3.65, 'unit': 'per unattached EIP'},
    }
    
    # Production keywords - buckets with these names are likely in use
    production_keywords = [
        'prod', 'production', 'app', 'data', 'backup', 'reports', 
        'logs', 'assets', 'uploads', 'archive', 'static', 'media'
    ]
    
    # Reason strings per resource type
    orphan_reasons = {
        's3_bucket':       'Empty S3 bucket with no active use',
        'security_group':  'Security group not attached to any resource',
        'ebs_volume':      'Unattached EBS volume (available state)',
        'elastic_ip':      'Elastic IP not associated with any instance',
        'ec2_instance':    'EC2 instance with no network relationships',
        'rds_instance':    'RDS instance with no security group attachments',
        'lambda_function': 'Lambda function with no role, VPC, or secret refs',
        'load_balancer':   'Load balancer with no target instances',
    }

    for node in graph.nodes:
        node_id = node['id']
        node_type = node['type']
        
        # Get inbound and outbound connections
        inbound = graph.get_inbound(node_id)
        outbound = graph.get_outbound(node_id)
        
        # Resource is orphaned if it has NO connections at all
        if len(inbound) == 0 and len(outbound) == 0:
            # Special handling for S3 buckets to avoid false positives
            if node_type == 's3_bucket':
                bucket_name = node_id.lower()
                is_empty = node['metadata'].get('is_empty', False)
                
                # Skip bucket if it's not empty (has objects stored)
                if not is_empty:
                    continue
                
                # Skip bucket if name contains production keywords
                has_production_keyword = any(keyword in bucket_name for keyword in production_keywords)
                if has_production_keyword:
                    continue
            
            # EBS volumes: cost is dynamic (size_gb × $0.10/mo)
            if node_type == 'ebs_volume':
                size_gb = node.get('metadata', {}).get('size_gb', 0)
                cost = round(size_gb * 0.10, 2)
                orphaned.append({
                    **node,
                    'estimated_monthly_cost': cost,
                    'cost_unit': f"{size_gb}GB × $0.10/mo",
                    'reason': orphan_reasons['ebs_volume'],
                })
                continue

            # Elastic IPs: only flag unattached ones
            if node_type == 'elastic_ip':
                if not node.get('metadata', {}).get('is_attached', True):
                    orphaned.append({
                        **node,
                        'estimated_monthly_cost': 3.65,
                        'cost_unit': 'per unattached EIP',
                        'reason': orphan_reasons['elastic_ip'],
                    })
                continue

            # Security groups: flag if unattached (no instances, no internet edges)
            if node_type == 'security_group':
                orphaned.append({
                    **node,
                    'estimated_monthly_cost': 0.0,
                    'cost_unit': 'security hygiene',
                    'reason': orphan_reasons['security_group'],
                })
                continue

            cost_info = cost_estimates.get(node_type, {'amount': 0.0, 'unit': 'unknown'})
            
            orphaned.append({
                'id': node_id,
                'type': node_type,
                'label': node['label'],
                'metadata': node['metadata'],
                'estimated_monthly_cost': cost_info['amount'],
                'cost_unit': cost_info['unit'],
                'reason': orphan_reasons.get(node_type, 'Orphaned resource — no active relationships'),
            })
    
    return orphaned


def find_attack_path(graph: Graph, resource_id: str, max_hops: int = 5) -> List[Dict[str, Any]]:
    """
    Find attack path from a resource to data stores using BFS traversal.
    
    Performs breadth-first search from the given resource_id, following outbound edges
    until reaching a data store node (rds_instance, s3_bucket, secrets_manager_secret).
    Stops traversal once depth exceeds max_hops.
    
    Args:
        graph: Infrastructure graph to analyze
        resource_id: Starting resource ID for attack path analysis
        max_hops: Maximum BFS depth before stopping (default 5)
    
    Returns:
        Ordered list of node dictionaries representing the full attack path.
        Returns empty list if no path to data store is found.
    """
    from collections import deque
    
    # Target node types that represent data stores
    data_store_types = {'rds_instance', 's3_bucket', 'secrets_manager_secret', 'dynamodb_table'}
    
    # Check if starting resource exists
    start_node = graph.get_node(resource_id)
    if not start_node:
        return []
    
    # BFS setup - queue stores (current_id, path_to_current, depth)
    queue = deque([(resource_id, [start_node], 0)])
    visited = {resource_id}
    
    while queue:
        current_id, path, depth = queue.popleft()
        current_node = graph.get_node(current_id)
        
        # Check if current node is a data store
        if current_node and current_node['type'] in data_store_types:
            return path
        
        # Stop expanding if we've reached the hop limit
        if depth >= max_hops:
            continue
        
        # Explore both outbound AND inbound neighbors - lateral movement goes both ways
        # e.g. EC2 → SG (outbound), RDS → SG (outbound from RDS = inbound to SG)
        # Following only outbound misses EC2→SG←RDS paths
        neighbors = graph.get_neighbors(current_id)
        for neighbor in neighbors:
            neighbor_id = neighbor['id']
            if neighbor_id not in visited:
                visited.add(neighbor_id)
                new_path = path + [neighbor]
                queue.append((neighbor_id, new_path, depth + 1))
    
    # No path to data store found
    return []


def calculate_blast_radius(graph: Graph, resource_id: str, max_hops: int = 5) -> Dict[str, Any]:
    """
    Calculate blast radius from a resource using DIRECTIONAL BFS (outbound only).
    
    Performs breadth-first search from the given resource_id, traversing ONLY
    outbound edges (downstream from the compromised resource). This answers:
    "If this resource is compromised, what can an attacker reach FROM here?"
    
    Does NOT traverse inbound edges (upstream), which would inflate the count
    with resources that protect/contain this resource rather than resources at risk.
    
    Args:
        graph: Infrastructure graph to analyze
        resource_id: Starting resource ID for blast radius calculation
        max_hops: Maximum BFS depth before stopping (default 5)
    
    Returns:
        Dictionary with count of reachable resources and list of resource IDs:
        {"count": int, "resource_ids": [list of strings]}
    """
    from collections import deque
    
    # Check if starting resource exists
    start_node = graph.get_node(resource_id)
    if not start_node:
        return {"count": 0, "resource_ids": []}
    
    # BFS setup - queue stores (current_id, depth)
    queue = deque([(resource_id, 0)])
    visited = {resource_id}
    
    while queue:
        current_id, depth = queue.popleft()
        
        # Stop expanding if we've reached the hop limit
        if depth >= max_hops:
            continue
        
        # Get OUTBOUND neighbors only (edges where current_id is the source)
        # Also include edges where current_id is the TARGET of "REACHES" or
        # "REACHES_VIA_SG" relationships (internet reaching into infra)
        outbound_ids = set()
        
        # Outbound: edges FROM this node
        for edge in graph._edges_by_source.get(current_id, []):
            outbound_ids.add(edge['to'])
        
        # Also follow inbound REACHES edges (internet → resource means resource is exposed)
        # If something REACHES us, the things we connect to are at risk
        for edge in graph._edges_by_target.get(current_id, []):
            if edge['relationship'] in ('REACHES', 'REACHES_VIA_SG', 'attached_to_instance', 'targets_instance', 'contains_resource'):
                outbound_ids.add(edge['from'])
        
        for neighbor_id in outbound_ids:
            if neighbor_id not in visited and neighbor_id != 'INTERNET':
                visited.add(neighbor_id)
                queue.append((neighbor_id, depth + 1))
    
    # Remove the starting resource from the count (don't include self)
    reachable_ids = list(visited - {resource_id})
    
    return {
        "count": len(reachable_ids),
        "resource_ids": reachable_ids
    }


def find_critical_resources(graph: Graph, findings: List[Dict[str, Any]], top_n: int = 5) -> List[Dict[str, Any]]:
    """
    Identify the most critical nodes by counting how many findings reference each node
    via their attack_path lists.

    Ranking: (1) finding count descending, (2) max severity descending.

    Args:
        graph: Infrastructure graph
        findings: List of finding dicts (each may have 'attack_path', 'severity', 'blast_radius')
        top_n: Maximum number of results to return (default 5)

    Returns:
        List of dicts with node_id, label, type, finding_count, max_severity, blast_radius
    """
    SEVERITY_ORDER = {'Critical': 4, 'Moderate': 3, 'Low': 2, 'High': 1}

    # Count findings per node and track max severity + blast radius
    node_finding_count: Dict[str, int] = {}
    node_max_severity: Dict[str, str] = {}
    node_blast_radius: Dict[str, int] = {}

    for finding in findings:
        path = finding.get('attack_path', [])
        blast = finding.get('blast_radius', 0) or 0
        # Mirror graph endpoint: if no path but blast_radius > 0, use resource_id
        if not path and blast > 0 and finding.get('resource_id'):
            path = [finding['resource_id']]
        if not path:
            continue
        severity = finding.get('severity', 'Low')

        for node_id in path:
            node_finding_count[node_id] = node_finding_count.get(node_id, 0) + 1
            # Keep highest severity seen for this node
            current = node_max_severity.get(node_id, 'Low')
            if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(current, 0):
                node_max_severity[node_id] = severity
            # Keep highest blast radius seen for this node
            if blast > node_blast_radius.get(node_id, 0):
                node_blast_radius[node_id] = blast

    if not node_finding_count:
        return []

    # Sort: finding_count desc, then severity desc
    sorted_nodes = sorted(
        node_finding_count.keys(),
        key=lambda nid: (
            node_finding_count[nid],
            SEVERITY_ORDER.get(node_max_severity.get(nid, 'Low'), 0),
        ),
        reverse=True,
    )

    results = []
    for node_id in sorted_nodes[:top_n]:
        node = graph.get_node(node_id)
        if not node:
            continue
        results.append({
            'node_id': node_id,
            'label': node.get('label', node_id),
            'type': node.get('type', 'unknown'),
            'finding_count': node_finding_count[node_id],
            'max_severity': node_max_severity.get(node_id, 'Low'),
            'blast_radius': node_blast_radius.get(node_id, 0),
        })

    return results
