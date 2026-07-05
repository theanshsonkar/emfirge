from app.models import AWSInfrastructure, RiskFinding, ToxicCombo
from app.egraph import Graph, find_orphaned_resources, get_internet_reachable_set, get_attack_path_to
from typing import List, Optional, Set
from dataclasses import dataclass


@dataclass
class GraphContext:
    """
    Pre-computed graph intelligence passed to all graph-aware rules.
    Thread-safe: no global state, one instance per scan invocation.
    """
    graph: Optional[Graph]
    reachable: Set[str]          # Internet-reachable resource IDs (BFS from INTERNET)
    has_subnet_data: bool        # Whether we have positive subnet evidence for reachability

    @classmethod
    def build(cls, graph: Optional[Graph], infra: AWSInfrastructure) -> 'GraphContext':
        """Build a GraphContext from a graph and infrastructure data."""
        if not graph:
            return cls(graph=None, reachable=set(), has_subnet_data=False)
        reachable = get_internet_reachable_set(graph)
        has_subnet_data = len(infra.vpc.subnets) > 0
        return cls(graph=graph, reachable=reachable, has_subnet_data=has_subnet_data)

    def is_reachable(self, resource_id: str) -> Optional[bool]:
        """
        Check if a resource is internet-reachable.

        Returns:
            True  — resource IS reachable from internet (positive evidence)
            False — resource is NOT reachable (positive evidence of isolation)
            None  — cannot determine (no graph or no subnet data) → rules should NOT downgrade
        """
        if not self.graph:
            return None  # No graph available
        if not self.has_subnet_data:
            return None  # No subnet data = can't determine reachability (conservative)
        return resource_id in self.reachable

    def get_blast_radius(self, resource_id: str, max_hops: int = 5) -> int:
        """Count resources reachable from a given node (outbound BFS)."""
        if not self.graph:
            return 0
        visited = set()
        queue = [(resource_id, 0)]
        while queue:
            current, depth = queue.pop(0)
            if current in visited or depth > max_hops:
                continue
            visited.add(current)
            for edge in self.graph._edges_by_source.get(current, []):
                if edge['to'] not in visited:
                    queue.append((edge['to'], depth + 1))
        visited.discard(resource_id)
        return len(visited)

    def get_data_store_access_count(self, role_id: str) -> int:
        """Count data stores (S3, RDS, Secrets) accessible via can_access edges from a role."""
        if not self.graph:
            return 0
        accessible = self.graph.get_outbound(role_id, 'can_access')
        return len(accessible)

    def get_attack_path(self, resource_id: str) -> Optional[List[str]]:
        """Get BFS path from INTERNET to this resource. None if not reachable."""
        if not self.graph:
            return None
        return get_attack_path_to(self.graph, resource_id)

# ── PORT CLASSIFICATION TABLE ─────────────────────────────────────
PORT_CLASSES = {
    22: "ADMIN", 3389: "ADMIN", 5985: "ADMIN", 5986: "ADMIN",
    5900: "ADMIN", 5901: "ADMIN", 2375: "ADMIN", 2376: "ADMIN",
    3306: "DATABASE", 5432: "DATABASE", 27017: "DATABASE",
    6379: "DATABASE", 1521: "DATABASE", 9042: "DATABASE", 1433: "DATABASE",
    8080: "INTERNAL", 3000: "INTERNAL", 5000: "INTERNAL",
    9000: "INTERNAL", 9090: "INTERNAL", 8443: "INTERNAL", 8888: "INTERNAL",
    80: "WEB", 443: "WEB",
}

# ── HELPER FUNCTIONS ──────────────────────────────────────────────

def is_intentional_resource(resource_tags: dict) -> bool:
    if not resource_tags:
        return False
    if resource_tags.get('emfirge:ignore') == 'true':
        return True
    if resource_tags.get('emfirge:role') in ['webserver', 'bastion', 'backend', 'database']:
        return True
    return False

def is_likely_dev(resource_name: str) -> bool:
    if not resource_name:
        return False
    dev_keywords = ['test', 'dev', 'staging', 'temp', 'demo', 'sandbox']
    return any(k in resource_name.lower() for k in dev_keywords)

def is_behind_load_balancer(graph, resource_id: str) -> bool:
    if not graph or not resource_id:
        return False
    try:
        inbound = graph.get_inbound(resource_id)
        return any('load_balancer' in n.get('type', '') for n in inbound)
    except:
        return False

# ── EC2 RULES ─────────────────────────────────────────────────────

def check_single_ec2_no_alb(infra: AWSInfrastructure, graph: Optional[Graph] = None, ctx: Optional['GraphContext'] = None) -> Optional[RiskFinding]:
    # If only 1 server and no load balancer, app goes down if server crashes
    # UPGRADED: Add blast_radius = count of resources that depend on this single instance
    if infra.ec2.instance_count == 1 and not infra.ec2.has_load_balancer:
        blast = 0
        instance_id = infra.ec2.instance_ids[0] if infra.ec2.instance_ids else None
        if graph and instance_id:
            # Count outbound connections from this instance (what depends on it)
            outbound = graph.get_outbound(instance_id)
            blast = len(outbound)

        return RiskFinding(
            rule_id='EMFIRGE-EC2-001',
            category='Availability',
            severity='Low',
            raw_severity='Low',
            issue='Single EC2 instance with no load balancer detected',
            recommendation='Add an Application Load Balancer and run minimum 2 EC2 instances for high availability',
            aws_service='EC2',
            resource_id=instance_id,
            resource_type='ec2_instance',
            region=infra.region,
            blast_radius=blast
        )
    return None

def check_ssh_open(infra: AWSInfrastructure, graph: Optional[Graph] = None, ctx: Optional['GraphContext'] = None) -> Optional[RiskFinding]:
    if infra.ec2.ssh_open_to_internet:
        severity = 'Critical'  # Default severity
        confidence = 'HIGH'    # Default confidence
        issue_suffix = ''
        recommendation_suffix = ''
        
        # If graph is available, check if instances using this SG are behind a load balancer
        if graph and infra.ec2.ssh_security_group_id:
            sg_id = infra.ec2.ssh_security_group_id
            
            # Find instances attached to this security group
            sg_node = graph.get_node(sg_id)
            if sg_node:
                attached_instances = sg_node['metadata'].get('attached_instances', [])
                
                # Check if any of these instances are behind a load balancer
                behind_lb = False
                for instance_id in attached_instances:
                    # Get inbound connections to this instance
                    inbound = graph.get_inbound(instance_id, relationship_type='targets_instance')
                    if any(node['type'] == 'load_balancer' for node in inbound):
                        behind_lb = True
                        break
                
                # If behind load balancer, downgrade to Low — likely intentional
                if behind_lb:
                    severity = 'Low'
                    confidence = 'LOW'
                    issue_suffix = ' — instances are behind load balancer'
                    recommendation_suffix = ' or use AWS Systems Manager Session Manager for secure access'
                
                # Check for dev environment naming
                for instance_id in attached_instances:
                    if is_likely_dev(instance_id):
                        if severity == 'Critical':
                            severity = 'Moderate'
                            confidence = 'LOW'
                        issue_suffix += ' — may be intentional in dev environment'
                        break
        
        return RiskFinding(
            rule_id='EMFIRGE-EC2-002',
            category='Security',
            severity=severity,
            confidence=confidence,
            issue='SSH port 22 is open to the entire internet (0.0.0.0/0)' + issue_suffix,
            recommendation='Restrict SSH access to your specific IP address only' + recommendation_suffix,
            aws_service='EC2',
            resource_id=infra.ec2.ssh_security_group_id,
            resource_type='security_group',
            region=infra.region
        )
    return None

def check_rdp_open(infra: AWSInfrastructure, graph: Optional[Graph] = None, ctx: Optional['GraphContext'] = None) -> Optional[RiskFinding]:
    # RDP port open to internet = Windows servers vulnerable to brute force attacks
    # UPGRADED: Use graph to check if instances are behind LB or in private subnet
    if infra.ec2.rdp_open_to_internet:
        severity = 'Critical'
        confidence = 'HIGH'
        issue_suffix = ''
        recommendation_suffix = ''

        # If graph is available, check if instances using this SG are protected
        if graph and infra.ec2.rdp_security_group_id:
            sg_id = infra.ec2.rdp_security_group_id
            sg_node = graph.get_node(sg_id)
            if sg_node:
                attached_instances = sg_node['metadata'].get('attached_instances', [])

                # Check if any of these instances are behind a load balancer
                behind_lb = False
                for instance_id in attached_instances:
                    inbound = graph.get_inbound(instance_id, relationship_type='targets_instance')
                    if any(node['type'] == 'load_balancer' for node in inbound):
                        behind_lb = True
                        break

                if behind_lb:
                    severity = 'Low'
                    confidence = 'LOW'
                    issue_suffix = ' — instances are behind load balancer'
                    recommendation_suffix = ' or use AWS Systems Manager Session Manager for secure access'

                # Check for dev environment naming
                if severity == 'Critical':
                    for instance_id in attached_instances:
                        if is_likely_dev(instance_id):
                            severity = 'Moderate'
                            confidence = 'LOW'
                            issue_suffix += ' — may be intentional in dev environment'
                            break

        return RiskFinding(
            rule_id='EMFIRGE-EC2-003',
            category='Security',
            severity=severity,
            raw_severity='Critical',
            confidence=confidence,
            issue='RDP port 3389 is open to the entire internet (0.0.0.0/0)' + issue_suffix,
            recommendation='Restrict RDP access to your specific IP address only' + recommendation_suffix,
            aws_service='EC2',
            resource_id=infra.ec2.rdp_security_group_id,
            resource_type='security_group',
            region=infra.region
        )
    return None

def check_no_auto_scaling(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # No auto scaling means app crashes during traffic spikes
    # Low severity — solo devs and small teams often don't need ASG intentionally
    if not infra.ec2.auto_scaling_enabled and infra.ec2.instance_count > 0:
        return RiskFinding(
            rule_id='EMFIRGE-EC2-004',
            category='Availability',
            severity='Low',
            issue='No Auto Scaling group configured',
            recommendation='Consider setting up Auto Scaling to handle traffic spikes and improve fault tolerance',
            aws_service='EC2',
            resource_id=infra.ec2.instance_ids[0] if infra.ec2.instance_ids else None,
            resource_type='ec2_instance',
            region=infra.region
        )
    return None

def check_expensive_instance(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # Paid instance types detected — may incur unexpected costs for new users
    if not infra.ec2.free_tier_eligible and infra.ec2.instance_count > 0:
        return RiskFinding(
            rule_id='EMFIRGE-EC2-005',
            category='Cost',
            severity='Moderate',
            issue=f'Paid instance types detected: {", ".join(infra.ec2.instance_types)} — these incur hourly charges',
            recommendation='If this is a dev or test environment, consider switching to t2.micro or t3.micro to minimize costs. If this is intentional for production, you can ignore this.',
            aws_service='EC2',
            resource_id=infra.ec2.instance_ids[0] if infra.ec2.instance_ids else None,
            resource_type='ec2_instance',
            region=infra.region
        )
    return None

def check_stopped_instances(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # Stopped instances still incur EBS storage costs
    if len(infra.ec2.stopped_instances) > 0:
        return RiskFinding(
            rule_id='EMFIRGE-EC2-006',
            category='Cost',
            severity='Low',
            issue=f'{len(infra.ec2.stopped_instances)} stopped EC2 instance(s) detected',
            recommendation='Terminate stopped instances you no longer need to avoid unnecessary storage costs',
            aws_service='EC2',
            resource_id=', '.join(infra.ec2.stopped_instances),
            resource_type='ec2_instance',
            region=infra.region
        )
    return None

def check_dangerous_open_ports(infra: AWSInfrastructure, graph: Optional[Graph] = None, ctx: Optional['GraphContext'] = None) -> List[RiskFinding]:
    # Catch all dangerous ports open to the internet beyond SSH (22) and RDP (3389)
    # which are already handled by dedicated rules.
    # UPGRADED: Downgrade if SG is attached to instances in private subnets (not internet-reachable)
    findings = []
    seen = set()  # deduplicate (sg_id, port) pairs

    # Pre-compute reachability once for all SGs
    reachable = ctx.reachable if ctx else (get_internet_reachable_set(graph) if graph else set())
    has_subnet_data = ctx.has_subnet_data if ctx else (len(infra.vpc.subnets) > 0 if graph else False)

    for sg in infra.ec2.security_groups:
        sg_id = sg.id
        attached_to = sg.attached_to

        # Determine if attached instances are internet-reachable
        # Only downgrade if we have positive evidence (has_subnet_data=True and none reachable)
        sg_not_reachable = False
        if graph and has_subnet_data and attached_to:
            sg_not_reachable = not any(iid in reachable for iid in attached_to)

        for rule in sg.rules:
            ip_ranges = rule.get('ip_ranges', [])
            # Only care about rules open to the entire internet
            if '0.0.0.0/0' not in ip_ranges and '::/0' not in ip_ranges:
                continue

            from_port = rule.get('from_port')
            to_port = rule.get('to_port')

            # Wide-open range: all ports exposed
            if from_port == 0 and to_port == 65535:
                key = (sg_id, 'ALL')
                if key not in seen:
                    seen.add(key)
                    severity = 'Moderate' if sg_not_reachable else 'Critical'
                    suffix = ' (not internet-reachable)' if sg_not_reachable else ''
                    findings.append(RiskFinding(
                        rule_id='EMFIRGE-EC2-010',
                        category='Security',
                        severity=severity,
                        raw_severity='Critical',
                        confidence='HIGH' if not sg_not_reachable else 'MEDIUM',
                        issue=f'All ports (0–65535) open to the internet on security group {sg_id}{suffix}',
                        recommendation='Restrict inbound rules to only the specific ports your application requires',
                        aws_service='EC2',
                        resource_id=sg_id,
                        resource_type='security_group',
                        region=infra.region
                    ))
                continue

            # Iterate every port in the rule range
            if from_port is None or to_port is None:
                continue

            # Fast-path: wide range (>1000 ports) — treat as effectively wide-open
            if to_port - from_port > 1000:
                key = (sg_id, f'WIDE:{from_port}-{to_port}')
                if key not in seen:
                    seen.add(key)
                    severity = 'Moderate' if sg_not_reachable else 'Critical'
                    suffix = ' (not internet-reachable)' if sg_not_reachable else ''
                    findings.append(RiskFinding(
                        rule_id='EMFIRGE-EC2-010',
                        category='Security',
                        severity=severity,
                        raw_severity='Critical',
                        confidence='HIGH' if not sg_not_reachable else 'MEDIUM',
                        issue=f'Wide port range {from_port}–{to_port} open to the internet on security group {sg_id}{suffix}',
                        recommendation='Restrict inbound rules to only the specific ports your application requires',
                        aws_service='EC2',
                        resource_id=sg_id,
                        resource_type='security_group',
                        region=infra.region
                    ))
                continue

            for port in range(from_port, to_port + 1):
                # Skip ports already covered by dedicated rules
                if port in (22, 3389):
                    continue

                key = (sg_id, port)
                if key in seen:
                    continue
                seen.add(key)

                port_class = PORT_CLASSES.get(port)

                if port_class == 'WEB':
                    # Web ports (80/443) open to internet are expected — no finding
                    continue
                elif port_class == 'ADMIN':
                    severity = 'Moderate' if sg_not_reachable else 'Critical'
                    suffix = ' (not internet-reachable)' if sg_not_reachable else ''
                    findings.append(RiskFinding(
                        rule_id='EMFIRGE-EC2-011',
                        category='Security',
                        severity=severity,
                        raw_severity='Critical',
                        confidence='HIGH' if not sg_not_reachable else 'MEDIUM',
                        issue=f'Admin port {port} open to the internet on security group {sg_id}{suffix}',
                        recommendation=f'Restrict port {port} to specific trusted IPs only. Admin protocols should never be exposed to the public internet.',
                        aws_service='EC2',
                        resource_id=sg_id,
                        resource_type='security_group',
                        region=infra.region
                    ))
                elif port_class == 'DATABASE':
                    severity = 'Moderate' if sg_not_reachable else 'Critical'
                    suffix = ' (not internet-reachable)' if sg_not_reachable else ''
                    findings.append(RiskFinding(
                        rule_id='EMFIRGE-EC2-012',
                        category='Security',
                        severity=severity,
                        raw_severity='Critical',
                        confidence='HIGH' if not sg_not_reachable else 'MEDIUM',
                        issue=f'Database port {port} open to the internet on security group {sg_id} — direct DB exposure{suffix}',
                        recommendation=f'Remove public access to port {port} immediately. Databases must never be directly reachable from the internet. Use a bastion host or VPN.',
                        aws_service='EC2',
                        resource_id=sg_id,
                        resource_type='security_group',
                        region=infra.region
                    ))
                elif port_class == 'INTERNAL':
                    severity = 'Low' if sg_not_reachable else 'Critical'
                    suffix = ' (not internet-reachable)' if sg_not_reachable else ''
                    findings.append(RiskFinding(
                        rule_id='EMFIRGE-EC2-013',
                        category='Security',
                        severity=severity,
                        raw_severity='Critical',
                        confidence='MEDIUM',
                        issue=f'Internal service port {port} open to the internet on security group {sg_id}{suffix}',
                        recommendation=f'Restrict port {port} to internal VPC CIDR ranges only. Internal services should not be publicly reachable.',
                        aws_service='EC2',
                        resource_id=sg_id,
                        resource_type='security_group',
                        region=infra.region
                    ))
                else:
                    # Port not in classification table — only downgrade if not reachable
                    severity = 'Low' if sg_not_reachable else 'Moderate'
                    suffix = ' (not internet-reachable)' if sg_not_reachable else ''
                    findings.append(RiskFinding(
                        rule_id='EMFIRGE-EC2-014',
                        category='Security',
                        severity=severity,
                        raw_severity='Moderate',
                        confidence='MEDIUM',
                        issue=f'Unusual port {port} open to the internet on security group {sg_id}{suffix}',
                        recommendation=f'Review whether port {port} needs to be publicly accessible. If not, restrict to specific IP ranges.',
                        aws_service='EC2',
                        resource_id=sg_id,
                        resource_type='security_group',
                        region=infra.region
                    ))

    return findings

def check_default_sg_open(infra: AWSInfrastructure, graph: Optional[Graph] = None, ctx: Optional['GraphContext'] = None) -> List[RiskFinding]:
    # Default SG with open inbound rules = any resource accidentally placed in it is exposed
    # AWS best practice: default SG should have zero inbound rules
    # UPGRADED: Downgrade if no instances attached or attached instances not internet-reachable
    findings = []

    # Pre-compute reachability once
    reachable = ctx.reachable if ctx else (get_internet_reachable_set(graph) if graph else set())
    has_subnet_data = ctx.has_subnet_data if ctx else (len(infra.vpc.subnets) > 0 if graph else False)

    for sg in infra.ec2.security_groups:
        if sg.name != 'default':
            continue
        for rule in sg.rules:
            ip_ranges = rule.get('ip_ranges', [])
            if '0.0.0.0/0' in ip_ranges or '::/0' in ip_ranges:
                severity = 'Critical'
                confidence = 'HIGH'
                issue_suffix = ''

                # Graph-aware downgrade
                if graph and has_subnet_data:
                    attached = sg.attached_to
                    if not attached:
                        # No instances using this SG — lower risk
                        severity = 'Low'
                        confidence = 'LOW'
                        issue_suffix = ' — no instances currently attached'
                    elif not any(iid in reachable for iid in attached):
                        # Instances exist but not internet-reachable
                        severity = 'Moderate'
                        confidence = 'MEDIUM'
                        issue_suffix = ' — attached instances not internet-reachable'

                findings.append(RiskFinding(
                    rule_id='EMFIRGE-EC2-015',
                    category='Security',
                    severity=severity,
                    raw_severity='Critical',
                    confidence=confidence,
                    issue='Default security group allows inbound traffic from the internet' + issue_suffix,
                    recommendation='Remove all inbound rules from the default security group. Use custom SGs for all resources.',
                    aws_service='EC2',
                    resource_id=sg.id,
                    resource_type='security_group',
                    region=infra.region
                ))
                break  # one finding per default SG, not one per rule
    return findings

def check_imdsv1_enabled(infra: AWSInfrastructure, graph: Optional[Graph] = None, ctx: Optional['GraphContext'] = None) -> List[RiskFinding]:
    # IMDSv1 allows unauthenticated HTTP requests to the metadata service
    # Exploitable via SSRF — used in the Capital One breach to steal IAM credentials
    # UPGRADED: Upgrade to Critical if instance is internet-reachable (SSRF exploitable)
    findings = []
    # Build reachable set once for all instances
    reachable = ctx.reachable if ctx else (get_internet_reachable_set(graph) if graph else set())
    has_subnet_data = ctx.has_subnet_data if ctx else (len(infra.vpc.subnets) > 0 if graph else False)

    for instance in infra.ec2.instances:
        if not instance.imdsv2_required:
            # Default: Moderate (as before)
            severity = 'Moderate'
            confidence = 'HIGH'
            issue_suffix = ''

            # Only upgrade if we have positive evidence of reachability
            if graph and has_subnet_data and instance.id in reachable:
                severity = 'Critical'
                confidence = 'HIGH'
                issue_suffix = ' — internet-reachable (SSRF exploitable)'

            attack_path = get_attack_path_to(graph, instance.id) if (graph and instance.id in reachable) else None

            findings.append(RiskFinding(
                rule_id='EMFIRGE-EC2-016',
                category='Security',
                severity=severity,
                raw_severity='Moderate',
                confidence=confidence,
                issue=f'EC2 instance {instance.id} has IMDSv1 enabled — vulnerable to SSRF credential theft' + issue_suffix,
                recommendation="Set HttpTokens to 'required' on instance metadata options to enforce IMDSv2",
                aws_service='EC2',
                resource_id=instance.id,
                resource_type='ec2_instance',
                region=infra.region,
                attack_path=attack_path
            ))
    return findings

# ── S3 RULES ──────────────────────────────────────────────────────

def check_public_s3_context_aware(infra: AWSInfrastructure, graph: Optional[Graph] = None, ctx: Optional['GraphContext'] = None) -> List[RiskFinding]:
    findings = []
    for bucket in infra.s3.public_buckets:
        bucket_lower = bucket.lower()
        
        # Check if bucket has CloudFront neighbor using graph
        has_cloudfront = False
        if graph:
            bucket_node = graph.get_node(bucket)
            if bucket_node:
                # Check if there's a CloudFront distribution serving from this bucket
                inbound = graph.get_inbound(bucket, relationship_type='serves_from_bucket')
                has_cloudfront = any(node['type'] == 'cloudfront_distribution' for node in inbound)
        
        # Check if this is likely a dev environment
        is_dev_bucket = is_likely_dev(bucket)
        
        # Determine severity and confidence based on CloudFront, naming patterns, and dev environment
        if has_cloudfront:
            # Bucket with CloudFront is likely intentional (website/CDN)
            severity = 'Low'
            confidence = 'LOW'
            issue_suffix = ' — served via CloudFront (likely intentional)'
        elif any(keyword in bucket_lower for keyword in ['website', 'static', 'public', 'assets']):
            # Website/static buckets without CloudFront
            severity = 'Moderate'
            confidence = 'MEDIUM'
            issue_suffix = ' — consider adding CloudFront for better security and performance'
        elif any(keyword in bucket_lower for keyword in ['prod', 'production', 'data', 'backup']):
            # Critical: production/data buckets should never be public
            severity = 'Critical'
            confidence = 'HIGH'
            issue_suffix = ' — production/data bucket should NEVER be public'
        elif any(keyword in bucket_lower for keyword in ['log', 'logs']):
            # Moderate: log buckets
            severity = 'Moderate'
            confidence = 'MEDIUM'
            issue_suffix = ' — log bucket should be private'
        else:
            # Default severity based on dev environment
            severity = 'Moderate' if is_dev_bucket else 'Critical'
            confidence = 'LOW' if is_dev_bucket else 'HIGH'
            issue_suffix = ' — may be intentional in dev environment' if is_dev_bucket else ''
        
        # Apply dev environment downgrade
        if is_dev_bucket and severity == 'Critical':
            severity = 'Moderate'
            confidence = 'LOW'
            if not issue_suffix:
                issue_suffix = ' — may be intentional in dev environment'
        
        findings.append(RiskFinding(
            rule_id='EMFIRGE-S3-001',
            category='Security',
            severity=severity,
            confidence=confidence,
            issue=f'Public S3 bucket detected: {bucket}{issue_suffix}',
            recommendation='Make bucket private immediately and use presigned URLs for sharing' if severity == 'Critical' 
                          else ('Add CloudFront distribution for better security and caching' if severity == 'Moderate' and 'CloudFront' in issue_suffix
                          else 'Review if public access is necessary. Consider making private and using presigned URLs.'),
            aws_service='S3',
            resource_id=bucket,
            resource_type='s3_bucket',
            region=infra.region
        ))
    return findings

def check_s3_encryption(infra: AWSInfrastructure, graph: Optional[Graph] = None, ctx: Optional['GraphContext'] = None) -> Optional[RiskFinding]:
    if len(infra.s3.unencrypted_buckets) > 0:
        severity = 'Moderate'
        attack_path = None

        if graph:
            reachable = ctx.reachable if ctx else get_internet_reachable_set(graph)
            has_subnet_data = ctx.has_subnet_data if ctx else len(infra.vpc.subnets) > 0
            if has_subnet_data:
                for bucket in infra.s3.unencrypted_buckets:
                    # Check if any internet-reachable role can_access this bucket
                    inbound = graph.get_inbound(bucket, 'can_access')
                    for role_node in inbound:
                        users = graph.get_inbound(role_node['id'], 'uses_iam_role')
                        reachable_user = next((u for u in users if u['id'] in reachable), None)
                        if reachable_user:
                            severity = 'Critical'
                            attack_path = get_attack_path_to(graph, bucket)
                            break
                    if severity == 'Critical':
                        break

        return RiskFinding(
            rule_id='EMFIRGE-S3-002',
            category='Security',
            severity=severity,
            raw_severity='Moderate',
            issue=f'S3 buckets without encryption: {", ".join(infra.s3.unencrypted_buckets)}',
            recommendation='Enable default encryption (SSE-S3) on all S3 buckets',
            aws_service='S3',
            resource_id=', '.join(infra.s3.unencrypted_buckets),
            resource_type='s3_bucket',
            region=infra.region,
            attack_path=attack_path
        )
    return None

def check_s3_versioning(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # No versioning = accidentally deleted files cannot be recovered
    # Low severity — log buckets, temp buckets, artifact buckets don't need versioning
    if len(infra.s3.buckets_without_versioning) > 0:
        return RiskFinding(
            rule_id='EMFIRGE-S3-003',
            category='Disaster Recovery',
            severity='Low',
            issue=f'S3 buckets without versioning: {", ".join(infra.s3.buckets_without_versioning)}',
            recommendation='Enable versioning on S3 buckets that store important data to protect against accidental deletion. Log or temporary buckets can be ignored.',
            aws_service='S3',
            resource_id=', '.join(infra.s3.buckets_without_versioning),
            resource_type='s3_bucket',
            region=infra.region
        )
    return None

def check_s3_no_logging(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # No access logging = no visibility into who accessed your buckets and when
    # Moderate severity — important for security auditing and incident response
    if len(infra.s3.buckets_without_logging) > 0:
        return RiskFinding(
            rule_id='EMFIRGE-S3-004',
            category='Security',
            severity='Moderate',
            confidence='HIGH',
            issue=f'S3 buckets without access logging enabled: {", ".join(infra.s3.buckets_without_logging)}',
            recommendation='Enable S3 server access logging to track requests made to your buckets. This is critical for security auditing, incident response, and compliance.',
            aws_service='S3',
            resource_id=', '.join(infra.s3.buckets_without_logging),
            resource_type='s3_bucket',
            region=infra.region
        )
    return None

# ── RDS RULES ─────────────────────────────────────────────────────

def check_rds_no_backup(infra: AWSInfrastructure, graph: Optional[Graph] = None, ctx: Optional['GraphContext'] = None) -> Optional[RiskFinding]:
    if infra.rds.instances and not infra.rds.backup_enabled:
        blast = 0
        if graph:
            for rds_id in infra.rds.instances:
                # Count inbound connections (compute → SG → RDS)
                inbound = graph.get_inbound(rds_id)
                blast += len(inbound)

        return RiskFinding(
            rule_id='EMFIRGE-RDS-001',
            category='Disaster Recovery',
            severity='Critical',
            raw_severity='Critical',
            confidence='HIGH',
            issue='RDS automated backups are disabled',
            recommendation='Enable automated backups with at least 7 days retention immediately',
            aws_service='RDS',
            resource_id=', '.join(infra.rds.instances),
            resource_type='rds_instance',
            region=infra.region,
            blast_radius=blast
        )
    return None

def check_rds_public(infra: AWSInfrastructure, graph: Optional[Graph] = None, ctx: Optional['GraphContext'] = None) -> Optional[RiskFinding]:
    if len(infra.rds.publicly_accessible) > 0:
        severity = 'Critical'   # Default severity
        confidence = 'HIGH'     # Default confidence
        
        # If graph is available, check if RDS instances are in private subnets
        if graph:
            # Check each RDS instance
            for rds_id in infra.rds.publicly_accessible:
                rds_node = graph.get_node(rds_id)
                if rds_node:
                    # Get security groups attached to this RDS instance
                    sg_ids = rds_node['metadata'].get('security_groups', [])
                    
                    # If RDS has security groups restricting access, it's somewhat protected
                    # even if the public flag is on
                    if len(sg_ids) > 0:
                        # Check if any security group is overly permissive
                        has_restrictive_sg = False
                        for sg_id in sg_ids:
                            sg_node = graph.get_node(sg_id)
                            if sg_node:
                                rules = sg_node['metadata'].get('rules', [])
                                # Check if any rule allows 0.0.0.0/0
                                for rule in rules:
                                    ip_ranges = rule.get('ip_ranges', [])
                                    if '0.0.0.0/0' not in ip_ranges:
                                        has_restrictive_sg = True
                                        break
                        
                        # If security groups are restrictive, downgrade to Moderate
                        # (misconfigured but somewhat protected)
                        if has_restrictive_sg:
                            severity = 'Moderate'
                            confidence = 'MEDIUM'
                            break
        
        return RiskFinding(
            rule_id='EMFIRGE-RDS-002',
            category='Security',
            severity=severity,
            confidence=confidence,
            issue=f'RDS instances publicly accessible: {", ".join(infra.rds.publicly_accessible)}' +
                  (' — protected by security groups but public flag enabled' if severity == 'Moderate' else ''),
            recommendation='Disable public accessibility and use VPC private subnets for RDS' +
                          (' — also review security group rules to ensure they are restrictive' if severity == 'Moderate' else ''),
            aws_service='RDS',
            resource_id=', '.join(infra.rds.publicly_accessible),
            resource_type='rds_instance',
            region=infra.region
        )
    return None

def check_rds_encryption(infra: AWSInfrastructure, graph: Optional[Graph] = None, ctx: Optional['GraphContext'] = None) -> Optional[RiskFinding]:
    if len(infra.rds.unencrypted_instances) > 0:
        severity = 'Moderate'
        attack_path = None

        if graph:
            reachable = ctx.reachable if ctx else get_internet_reachable_set(graph)
            has_subnet_data = ctx.has_subnet_data if ctx else len(infra.vpc.subnets) > 0
            if has_subnet_data:
                for rds_id in infra.rds.unencrypted_instances:
                    # Check if any internet-reachable role can_access this RDS
                    inbound = graph.get_inbound(rds_id, 'can_access')
                    for role_node in inbound:
                        users = graph.get_inbound(role_node['id'], 'uses_iam_role')
                        if any(u['id'] in reachable for u in users):
                            severity = 'Critical'
                            attack_path = get_attack_path_to(graph, rds_id)
                            break
                    if severity == 'Critical':
                        break

        return RiskFinding(
            rule_id='EMFIRGE-RDS-003',
            category='Security',
            severity=severity,
            raw_severity='Moderate',
            issue=f'RDS instances without encryption: {", ".join(infra.rds.unencrypted_instances)}',
            recommendation='RDS encryption cannot be enabled on a running instance. To fix: take a snapshot of the instance, copy the snapshot with encryption enabled, then restore a new instance from the encrypted snapshot.',
            aws_service='RDS',
            resource_id=', '.join(infra.rds.unencrypted_instances),
            resource_type='rds_instance',
            region=infra.region,
            attack_path=attack_path
        )
    return None

def check_rds_deletion_protection(infra: AWSInfrastructure, graph: Optional[Graph] = None, ctx: Optional['GraphContext'] = None) -> Optional[RiskFinding]:
    if len(infra.rds.instances_without_deletion_protection) > 0:
        severity = 'Critical'
        confidence = 'MEDIUM'

        if graph:
            reachable = ctx.reachable if ctx else get_internet_reachable_set(graph)
            has_subnet_data = ctx.has_subnet_data if ctx else len(infra.vpc.subnets) > 0
            if has_subnet_data:
                all_private = all(
                    rds_id not in reachable
                    for rds_id in infra.rds.instances_without_deletion_protection
                )
                if all_private:
                    severity = 'Moderate'
                    confidence = 'MEDIUM'

        return RiskFinding(
            rule_id='EMFIRGE-RDS-004',
            category='Disaster Recovery',
            severity=severity,
            raw_severity='Critical',
            confidence=confidence,
            issue=f'RDS instances without deletion protection enabled: {", ".join(infra.rds.instances_without_deletion_protection)}',
            recommendation='Enable deletion protection on each RDS instance. Go to RDS > Databases > select instance > Modify > Enable deletion protection. This prevents accidental or malicious permanent deletion of your database.',
            aws_service='RDS',
            resource_id=', '.join(infra.rds.instances_without_deletion_protection),
            resource_type='rds_instance',
            region=infra.region
        )
    return None

def check_rds_log_exports(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # No log exports = no visibility into database errors, slow queries, or audit trail
    if len(infra.rds.instances_without_log_exports) > 0:
        return RiskFinding(
            rule_id='EMFIRGE-RDS-005',
            category='Security',
            severity='Moderate',
            confidence='MEDIUM',
            issue=f'RDS instances without CloudWatch log exports enabled: {", ".join(infra.rds.instances_without_log_exports)}',
            recommendation='Enable CloudWatch log exports for each RDS instance. Go to RDS > Databases > select instance > Modify > Log exports > enable error, slowquery, and audit logs. This provides visibility into database activity and aids incident response.',
            aws_service='RDS',
            resource_id=', '.join(infra.rds.instances_without_log_exports),
            resource_type='rds_instance',
            region=infra.region
        )
    return None

# ── IAM RULES ─────────────────────────────────────────────────────

def check_root_access_keys(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # Root access keys = if leaked, attacker has full control of entire AWS account
    if infra.iam.root_has_access_keys:
        return RiskFinding(
            rule_id='EMFIRGE-IAM-001',
            category='Security',
            severity='Critical',
            confidence='HIGH',
            issue='Root account has active access keys',
            recommendation='Delete root access keys immediately and use IAM users instead',
            aws_service='IAM',
            resource_id='root-account',
            resource_type='iam_root',
            region='global'
        )
    return None

def check_iam_high_risk_users(infra: AWSInfrastructure, graph: Optional[Graph] = None, ctx: Optional['GraphContext'] = None) -> List[RiskFinding]:
    # Combined rule: users with BOTH old access keys AND no MFA = highest risk
    # UPGRADED: Add blast_radius = how many data stores this user can access
    findings = []
    
    # Extract usernames from old_access_keys (format: "username (X days)")
    old_key_users = {}
    for entry in infra.iam.old_access_keys:
        username = entry.split(' (')[0]
        old_key_users[username] = entry
    
    # Find users in both lists
    no_mfa_users = set(infra.iam.users_without_mfa)
    high_risk_users = set(old_key_users.keys()).intersection(no_mfa_users)
    
    for username in high_risk_users:
        age_info = old_key_users[username]
        
        # Calculate blast_radius: how many data stores can this user access?
        blast = 0
        if graph and username in infra.iam.users_with_admin_policy:
            # Admin user can access ALL data stores
            for node_type in ('s3_bucket', 'rds_instance', 'secretsmanager_secret', 'dynamodb_table', 'sqs_queue'):
                blast += len(graph.find_nodes_by_type(node_type))
        
        findings.append(RiskFinding(
                rule_id='EMFIRGE-IAM-002',
                category='Security',
                severity='Critical',
                confidence='HIGH',
                issue=f'IAM user {username} has old access keys ({age_info}) AND no MFA enabled',
                recommendation='Enable MFA immediately and rotate access keys. This user is at highest risk of account compromise.',
                aws_service='IAM',
                resource_id=username,
                resource_type='iam_user',
                region='global',
                blast_radius=blast
            ))
    
    return findings

def check_users_without_mfa(infra: AWSInfrastructure, ctx: Optional['GraphContext'] = None) -> List[RiskFinding]:
    # No MFA = one leaked password gives full account access
    # Check each user's console access to determine individual severity
    findings = []
    
    if len(infra.iam.users_without_mfa) > 0:
        # Create a mapping of username to console access
        user_console_access = {}
        if infra.iam.iam_users:
            user_console_access = {user.username: user.has_console_access for user in infra.iam.iam_users}
        
        # Create individual finding for each user without MFA
        for username in infra.iam.users_without_mfa:
            console_access = user_console_access.get(username)
            
            # Determine severity based on individual user's console access
            if console_access is False:
                # User has no console access - programmatic only (service account)
                severity = 'Low'
                confidence = 'MEDIUM'
                issue_suffix = ' — programmatic-only user (service account)'
            elif console_access is True:
                # User has console access - human user
                severity = 'Critical'
                confidence = 'HIGH'
                issue_suffix = ' — has console access'
            else:
                # Unknown console access - assume CRITICAL for safety
                severity = 'Critical'
                confidence = 'HIGH'
                issue_suffix = ' — console access unknown'
            
            findings.append(RiskFinding(
                rule_id='EMFIRGE-IAM-003',
                category='Security',
                severity=severity,
                confidence=confidence,
                issue=f'IAM user {username} has no MFA enabled{issue_suffix}',
                recommendation='Enable MFA for this IAM user if they have console access. Programmatic-only service accounts have lower MFA priority.',
                aws_service='IAM',
                resource_id=username,
                resource_type='iam_user',
                region='global'
            ))
    
    return findings

def check_old_access_keys(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # Old access keys sitting around increase the window of exposure if leaked
    # Low severity — service account keys are often intentionally long-lived
    if len(infra.iam.old_access_keys) > 0:
        return RiskFinding(
            rule_id='EMFIRGE-IAM-004',
            category='Security',
            severity='Low',
            issue=f'Access keys older than 90 days: {", ".join(infra.iam.old_access_keys)}',
            recommendation='Rotate access keys every 90 days as a security best practice. If these are service account keys, update all systems that use them before rotating.',
            aws_service='IAM',
            resource_id=', '.join(infra.iam.old_access_keys),
            resource_type='iam_access_key',
            region='global'
        )
    return None

def check_root_used_recently(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # Root account should never be used for daily work — only for emergencies
    if infra.iam.root_used_recently:
        return RiskFinding(
            rule_id='EMFIRGE-IAM-005',
            category='Security',
            severity='Moderate',
            issue='Root account was used in the last 30 days',
            recommendation='Stop using root account for daily tasks. Create an IAM admin user instead',
            aws_service='IAM',
            resource_id='root-account',
            resource_type='iam_root',
            region='global'
        )
    return None

def check_iam_wildcard_policy(infra: AWSInfrastructure, graph: Optional[Graph] = None, ctx: Optional['GraphContext'] = None) -> List[RiskFinding]:
    findings = []
    for username in infra.iam.users_with_admin_policy:
        blast = 0
        if graph:
            # Admin can access ALL data stores — count them
            for node_type in ['s3_bucket', 'rds_instance', 'secretsmanager_secret']:
                blast += len(graph.find_nodes_by_type(node_type))

        findings.append(RiskFinding(
            rule_id='EMFIRGE-IAM-006',
            category='Security',
            severity='Critical',
            raw_severity='Critical',
            confidence='HIGH',
            issue=f'IAM user {username} has full admin access (Action:* Resource:*)',
            recommendation='Replace AdministratorAccess with least-privilege policies scoped to required services only',
            aws_service='IAM',
            resource_id=username,
            resource_type='iam_user',
            region='global',
            blast_radius=blast
        ))
    return findings

# ── CLOUDTRAIL RULES ──────────────────────────────────────────────

def check_cloudtrail_disabled(infra: AWSInfrastructure, graph: Optional[Graph] = None, ctx: Optional['GraphContext'] = None) -> Optional[RiskFinding]:
    if not infra.cloudtrail.is_enabled:
        severity = 'Moderate'

        if graph:
            reachable = ctx.reachable if ctx else get_internet_reachable_set(graph)
            has_subnet_data = ctx.has_subnet_data if ctx else len(infra.vpc.subnets) > 0
            if has_subnet_data and len(reachable) > 0:
                severity = 'Critical'

        return RiskFinding(
            rule_id='EMFIRGE-CT-001',
            category='Security',
            severity=severity,
            raw_severity='Moderate',
            issue='CloudTrail is not enabled',
            recommendation='Enable CloudTrail to maintain an audit log of all AWS account activity',
            aws_service='CloudTrail',
            resource_id='cloudtrail-not-configured',
            resource_type='cloudtrail',
            region=infra.region
        )
    return None

def check_cloudtrail_not_multiregion(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # Single region trail = activity in other regions is not being logged
    if infra.cloudtrail.is_enabled and not infra.cloudtrail.is_multi_region:
        return RiskFinding(
            rule_id='EMFIRGE-CT-002',
            category='Security',
            severity='Low',
            issue='CloudTrail is not configured for multi-region logging',
            recommendation='Only relevant if you use multiple AWS regions. If all your resources are in one region, this can be ignored. Otherwise enable multi-region CloudTrail to capture activity across all regions.',
            aws_service='CloudTrail',
            resource_id=infra.cloudtrail.trail_arn,
            resource_type='cloudtrail',
            region=infra.region
        )
    return None

# ── COST RULES ────────────────────────────────────────────────────

def check_no_budget_alerts(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # No budget alerts = surprise bill at end of month
    if not infra.cost.has_budget_alerts:
        return RiskFinding(
            rule_id='EMFIRGE-COST-001',
            category='Cost',
            severity='Moderate',
            issue='No AWS budget alerts configured',
            recommendation='Set up AWS Budgets with email alerts to avoid surprise bills',
            aws_service='Budgets',
            resource_id='aws-budgets',
            resource_type='budget',
            region='global'
        )
    return None

def check_no_billing_alarm(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # Only fires if BOTH budget alerts and billing alarm are missing
    # If user has Budgets configured, they are already protected — skip this rule
    if not infra.cost.has_billing_alarm and not infra.cost.has_budget_alerts:
        return RiskFinding(
            rule_id='EMFIRGE-COST-002',
            category='Cost',
            severity='Moderate',
            issue='No CloudWatch billing alarm configured',
            recommendation='Create a CloudWatch billing alarm to get notified when charges exceed your threshold',
            aws_service='CloudWatch',
            resource_id='cloudwatch-billing-alarm',
            resource_type='cloudwatch_alarm',
            region='us-east-1'
        )
    return None

def check_service_dominance(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # One service using >80% of bill = worth reviewing spend
    if infra.cost.top_service_percentage > 80 and infra.cost.monthly_cost > 5:
        return RiskFinding(
            rule_id='EMFIRGE-COST-003',
            category='Cost',
            severity='Low',
            issue=f'{infra.cost.top_service} accounts for {infra.cost.top_service_percentage}% of your bill',
            recommendation='Review your usage of this service and consider cost optimization strategies',
            aws_service='Cost Explorer',
            resource_id=infra.cost.top_service,
            resource_type='aws_service',
            region='global'
        )
    return None

# ── CLOUDWATCH RULES ──────────────────────────────────────────────

def check_no_cloudwatch(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # No monitoring = flying blind, no alerts when things go wrong
    if not infra.cloudwatch.has_alarms:
        return RiskFinding(
            rule_id='EMFIRGE-CW-001',
            category='Security',
            severity='Moderate',
            issue='No CloudWatch alarms configured',
            recommendation='Set up CloudWatch alarms for CPU usage, error rates, and application health',
            aws_service='CloudWatch',
            resource_id='cloudwatch-alarms',
            resource_type='cloudwatch_alarm',
            region=infra.region
        )
    return None

# ── GUARDDUTY RULES ───────────────────────────────────────────────

def check_guardduty_disabled(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # GuardDuty off = zero threat detection — you won't know if your account is actively being attacked
    # Moderate not Critical — your account isn't necessarily under attack right now,
    # but you have zero visibility if it is. Think of it like disabling your burglar alarm.
    if not infra.guardduty.is_enabled:
        return RiskFinding(
            rule_id='EMFIRGE-GD-001',
            category='Security',
            severity='Moderate',
            issue='Amazon GuardDuty is not enabled in this region',
            recommendation='Enable GuardDuty in the AWS console under Security, Identity & Compliance > GuardDuty. It takes one click and costs roughly $1-4/month for small accounts. It continuously monitors for compromised credentials, unusual API calls, and crypto mining activity.',
            aws_service='GuardDuty',
            resource_id='guardduty-not-configured',
            resource_type='guardduty_detector',
            region=infra.region
        )
    return None

# ── LAMBDA RULES ──────────────────────────────────────────────────

def check_lambda_admin_role(infra: AWSInfrastructure, graph: Optional[Graph] = None, ctx: Optional['GraphContext'] = None) -> Optional[RiskFinding]:
    # UPGRADED: Add blast_radius by counting can_access edges from the Lambda's role
    if len(infra.lambda_data.functions_with_admin_role) > 0:
        blast = 0
        attack_path = []

        if graph:
            for fn_name in infra.lambda_data.functions_with_admin_role:
                # Follow Lambda → IAM Role → can_access → data stores
                roles = graph.get_outbound(fn_name, 'uses_iam_role')
                for role in roles:
                    accessible = graph.get_outbound(role['id'], 'can_access')
                    blast += len(accessible)
                    if accessible and not attack_path:
                        attack_path = [fn_name, role['id'], accessible[0]['id']]

        return RiskFinding(
            rule_id='EMFIRGE-LAMBDA-001',
            category='Security',
            severity='Critical',
            raw_severity='Critical',
            confidence='HIGH',
            issue=f'Lambda functions with admin IAM permissions: {", ".join(infra.lambda_data.functions_with_admin_role)}',
            recommendation='Apply least-privilege IAM roles to Lambda functions. Each function should only have permissions for the specific AWS services it actually calls. Remove AdministratorAccess and create a custom role with only the required actions.',
            aws_service='Lambda',
            resource_id=', '.join(infra.lambda_data.functions_with_admin_role),
            resource_type='lambda_function',
            region=infra.region,
            blast_radius=blast,
            attack_path=attack_path
        )
    return None

def check_lambda_outdated_runtime(infra: AWSInfrastructure, graph: Optional[Graph] = None, ctx: Optional['GraphContext'] = None) -> Optional[RiskFinding]:
    # UPGRADED: Upgrade to Critical if any Lambda with outdated runtime is internet-reachable
    if len(infra.lambda_data.functions_with_outdated_runtime) > 0:
        severity = 'Moderate'
        confidence = 'HIGH'
        attack_path = None

        # Use ctx if available, otherwise compute
        reachable = ctx.reachable if ctx else (get_internet_reachable_set(graph) if graph else set())
        has_subnet_data = ctx.has_subnet_data if ctx else (len(infra.vpc.subnets) > 0 if graph else False)

        if graph and has_subnet_data:
            for fn_name in infra.lambda_data.functions_with_outdated_runtime:
                if fn_name in reachable:
                    severity = 'Critical'
                    confidence = 'HIGH'
                    attack_path = get_attack_path_to(graph, fn_name)
                    break

        return RiskFinding(
            rule_id='EMFIRGE-LAMBDA-002',
            category='Security',
            severity=severity,
            raw_severity='Moderate',
            confidence=confidence,
            issue=f'Lambda functions on deprecated runtimes: {", ".join(infra.lambda_data.functions_with_outdated_runtime)}',
            recommendation='Upgrade these functions to a supported runtime. Go to Lambda > Functions > select the function > Edit runtime settings. For Python: use python3.11 or python3.12. For Node.js: use nodejs20.x. Test thoroughly after upgrading as some APIs may have changed.',
            aws_service='Lambda',
            resource_id=', '.join(infra.lambda_data.functions_with_outdated_runtime),
            resource_type='lambda_function',
            region=infra.region,
            attack_path=attack_path
        )
    return None

def check_lambda_timeout(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # Default 3s timeout = function likely to time out on any real workload
    # Max 900s timeout = runaway function can silently cost hundreds of dollars
    if len(infra.lambda_data.functions_with_no_timeout) > 0:
        return RiskFinding(
            rule_id='EMFIRGE-LAMBDA-003',
            category='Cost',
            severity='Low',
            issue=f'Lambda functions with default (3s) or maximum (900s) timeout: {", ".join(infra.lambda_data.functions_with_no_timeout)}',
            recommendation='Set a timeout that reflects the actual expected execution time plus a reasonable buffer. For example, if your function typically runs in 5 seconds, set the timeout to 15 seconds. This prevents runaway executions from silently accumulating charges.',
            aws_service='Lambda',
            resource_id=', '.join(infra.lambda_data.functions_with_no_timeout),
            resource_type='lambda_function',
            region=infra.region
        )
    return None

# ── SECRETS MANAGER RULES ─────────────────────────────────────────

def check_secrets_not_rotated(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # Secrets that never rotate = if a secret leaks (via logs, git, breach),
    # it remains valid forever — giving an attacker permanent access
    if len(infra.secrets_manager.secrets_without_rotation) > 0:
        return RiskFinding(
            rule_id='EMFIRGE-SM-001',
            category='Security',
            severity='Low',
            issue=f'Secrets Manager secrets without rotation: {", ".join(infra.secrets_manager.secrets_without_rotation)}',
            recommendation='Enable automatic rotation for secrets that support it (RDS, Redshift, DocumentDB credentials have native rotation). For API keys or custom secrets, set up a Lambda rotation function or rotate them manually every 90 days.',
            aws_service='Secrets Manager',
            resource_id=', '.join(infra.secrets_manager.secrets_without_rotation),
            resource_type='secret',
            region=infra.region
        )
    return None

# ── VPC RULES ─────────────────────────────────────────────────────

def check_vpc_no_flow_logs(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # VPCs without flow logs = no visibility into network traffic patterns or security incidents
    if len(infra.vpc.vpcs_without_flow_logs) > 0:
        return RiskFinding(
            rule_id='EMFIRGE-VPC-001',
            category='Security',
            severity='Moderate',
            issue=f'VPCs without flow logs enabled: {", ".join(infra.vpc.vpcs_without_flow_logs)}',
            recommendation='Enable VPC Flow Logs for all VPCs to monitor network traffic and detect security threats. Go to VPC > Your VPCs > select VPC > Flow logs tab > Create flow log.',
            aws_service='VPC',
            resource_id=', '.join(infra.vpc.vpcs_without_flow_logs),
            resource_type='vpc',
            region=infra.region
        )
    return None

def check_default_vpc_in_use(infra: AWSInfrastructure, graph: Optional[Graph] = None, ctx: Optional['GraphContext'] = None) -> Optional[RiskFinding]:
    if infra.vpc.default_vpc_in_use:
        severity = 'Moderate'
        attack_path = None

        if graph:
            reachable = ctx.reachable if ctx else get_internet_reachable_set(graph)
            has_subnet_data = ctx.has_subnet_data if ctx else len(infra.vpc.subnets) > 0
            if has_subnet_data:
                # Check if any resource in the default VPC is internet-reachable
                for subnet in infra.vpc.subnets:
                    if isinstance(subnet, dict):
                        vpc_id = subnet.get('vpc_id')
                        resources = subnet.get('resources', [])
                    else:
                        vpc_id = subnet.vpc_id
                        resources = subnet.resources
                    if vpc_id == infra.vpc.default_vpc_id:
                        reachable_resource = next((r for r in resources if r in reachable), None)
                        if reachable_resource:
                            severity = 'Critical'
                            attack_path = get_attack_path_to(graph, reachable_resource)
                            break

        return RiskFinding(
            rule_id='EMFIRGE-VPC-002',
            category='Security',
            severity=severity,
            raw_severity='Moderate',
            issue=f'Default VPC is in use: {infra.vpc.default_vpc_id}',
            recommendation='Create a custom VPC with properly configured subnets and security groups. Default VPCs have less restrictive default settings and should not be used for production workloads.',
            aws_service='VPC',
            resource_id=infra.vpc.default_vpc_id,
            resource_type='vpc',
            region=infra.region,
            attack_path=attack_path
        )
    return None

def check_missing_vpc_endpoints(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # Missing VPC endpoints = traffic to S3/DynamoDB goes over internet instead of staying in AWS network
    missing_services = []
    if infra.vpc.missing_s3_endpoint:
        missing_services.append('S3')
    if infra.vpc.missing_dynamodb_endpoint:
        missing_services.append('DynamoDB')
    
    if len(missing_services) > 0 and infra.vpc.total_vpcs > 0:
        return RiskFinding(
            rule_id='EMFIRGE-VPC-003',
            category='Security',
            severity='Low',
            issue=f'VPC endpoints missing for: {", ".join(missing_services)}',
            recommendation='Create VPC endpoints for S3 and DynamoDB to keep traffic within the AWS network and reduce data transfer costs. Go to VPC > Endpoints > Create endpoint.',
            aws_service='VPC',
            resource_type='vpc_endpoint',
            region=infra.region
        )
    return None

# ── KMS RULES ─────────────────────────────────────────────────────

def check_kms_no_rotation(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # KMS keys without rotation = if a key is compromised, it remains valid indefinitely
    if len(infra.kms.cmks_without_rotation) > 0:
        return RiskFinding(
            rule_id='EMFIRGE-KMS-001',
            category='Security',
            severity='Moderate',
            issue=f'KMS customer-managed keys without automatic rotation: {", ".join(infra.kms.cmks_without_rotation)}',
            recommendation='Enable automatic key rotation for all customer-managed KMS keys. Go to KMS > Customer managed keys > select key > Key rotation tab > Enable automatic rotation. Keys will rotate annually.',
            aws_service='KMS',
            resource_id=', '.join(infra.kms.cmks_without_rotation),
            resource_type='kms_key',
            region=infra.region
        )
    return None

def check_kms_pending_deletion(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # Keys scheduled for deletion = data encrypted with these keys will become inaccessible
    if len(infra.kms.cmks_pending_deletion) > 0:
        return RiskFinding(
            rule_id='EMFIRGE-KMS-002',
            category='Security',
            severity='Critical',
            confidence='HIGH',
            issue=f'KMS keys scheduled for deletion: {", ".join(infra.kms.cmks_pending_deletion)}',
            recommendation='Cancel key deletion immediately if these keys are still in use. Data encrypted with deleted keys cannot be recovered. Go to KMS > Customer managed keys > select key > Cancel key deletion.',
            aws_service='KMS',
            resource_id=', '.join(infra.kms.cmks_pending_deletion),
            resource_type='kms_key',
            region=infra.region
        )
    return None

# ── AWS CONFIG RULES ──────────────────────────────────────────────

def check_config_disabled(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # AWS Config not enabled = no compliance monitoring or resource configuration tracking
    if not infra.config.is_enabled:
        return RiskFinding(
            rule_id='EMFIRGE-CFG-001',
            category='Security',
            severity='Moderate',
            issue='AWS Config is not enabled in this region',
            recommendation='Enable AWS Config to track resource configurations and compliance. Go to AWS Config > Get started > Set up AWS Config. This helps maintain security baselines and detect configuration drift.',
            aws_service='Config',
            resource_id='config-not-configured',
            resource_type='config_recorder',
            region=infra.region
        )
    return None

def check_config_non_compliant(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # Non-compliant Config rules = resources violating security or compliance policies
    if len(infra.config.non_compliant_rules) > 0:
        return RiskFinding(
            rule_id='EMFIRGE-CFG-002',
            category='Security',
            severity='Moderate',
            issue=f'AWS Config rules with non-compliant resources: {", ".join(infra.config.non_compliant_rules)}',
            recommendation='Review and remediate non-compliant resources in AWS Config. Go to AWS Config > Rules > select rule > view non-compliant resources. Address each violation to maintain security compliance.',
            aws_service='Config',
            resource_id=', '.join(infra.config.non_compliant_rules),
            resource_type='config_rule',
            region=infra.region
        )
    return None

# ── SNS RULES ─────────────────────────────────────────────────────

def check_sns_no_encryption(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # SNS topics without encryption = message data stored in plain text
    if len(infra.sns.topics_without_encryption) > 0:
        return RiskFinding(
            rule_id='EMFIRGE-SNS-001',
            category='Security',
            severity='Moderate',
            issue=f'SNS topics without encryption: {", ".join(infra.sns.topics_without_encryption)}',
            recommendation='Enable encryption for all SNS topics using AWS KMS. Go to SNS > Topics > select topic > Edit > Encryption > Enable encryption and select a KMS key.',
            aws_service='SNS',
            resource_id=', '.join(infra.sns.topics_without_encryption),
            resource_type='sns_topic',
            region=infra.region
        )
    return None

def check_sns_public_access(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # SNS topics with public access = anyone on the internet can publish or subscribe
    if len(infra.sns.topics_with_public_access) > 0:
        return RiskFinding(
            rule_id='EMFIRGE-SNS-002',
            category='Security',
            severity='Critical',
            confidence='HIGH',
            issue=f'SNS topics with public access policies: {", ".join(infra.sns.topics_with_public_access)}',
            recommendation='Remove public access from SNS topic policies immediately. Go to SNS > Topics > select topic > Edit > Access policy > Remove statements with Principal: "*". Use specific AWS account IDs or IAM roles instead.',
            aws_service='SNS',
            resource_id=', '.join(infra.sns.topics_with_public_access),
            resource_type='sns_topic',
            region=infra.region
        )
    return None

# ── ECS RULES ─────────────────────────────────────────────────────

def check_ecs_privileged_mode(infra: AWSInfrastructure, graph: Optional[Graph] = None, ctx: Optional['GraphContext'] = None) -> Optional[RiskFinding]:
    if len(infra.ecs.tasks_with_privileged_containers) > 0:
        blast = 0
        if graph:
            # Count data stores accessible via ECS task roles
            ecs_node = graph.get_node('ecs_tasks')
            if ecs_node:
                roles = graph.get_outbound('ecs_tasks', 'USES_ROLE')
                for role in roles:
                    accessible = graph.get_outbound(role['id'], 'can_access')
                    blast += len(accessible)

        return RiskFinding(
            rule_id='EMFIRGE-ECS-001',
            category='Security',
            severity='Critical',
            raw_severity='Critical',
            confidence='HIGH',
            issue=f'ECS task definitions with privileged containers: {", ".join(infra.ecs.tasks_with_privileged_containers)}',
            recommendation='Remove privileged mode from ECS containers immediately. Privileged containers have root access to the host system. Go to ECS > Task Definitions > create new revision > Container definitions > uncheck "Privileged".',
            aws_service='ECS',
            resource_id=', '.join(infra.ecs.tasks_with_privileged_containers),
            resource_type='ecs_task_definition',
            region=infra.region,
            blast_radius=blast
        )
    return None

def check_ecs_no_resource_limits(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    # Containers without resource limits = can consume all host resources, causing outages
    if len(infra.ecs.tasks_without_resource_limits) > 0:
        return RiskFinding(
            rule_id='EMFIRGE-ECS-002',
            category='Security',
            severity='Moderate',
            issue=f'ECS task definitions without CPU or memory limits: {", ".join(infra.ecs.tasks_without_resource_limits)}',
            recommendation='Set CPU and memory limits for all ECS containers to prevent resource exhaustion. Go to ECS > Task Definitions > create new revision > Container definitions > set Memory and CPU values.',
            aws_service='ECS',
            resource_id=', '.join(infra.ecs.tasks_without_resource_limits),
            resource_type='ecs_task_definition',
            region=infra.region
        )
    return None

# ── WAF RULES ─────────────────────────────────────────────────────

def check_waf_not_enabled(infra: AWSInfrastructure, graph: Optional[Graph] = None, ctx: Optional['GraphContext'] = None) -> Optional[RiskFinding]:
    if len(infra.waf.albs_without_waf) > 0:
        severity = 'Moderate'
        confidence = 'HIGH'
        attack_path = None

        # Use ctx if available, otherwise compute
        reachable = ctx.reachable if ctx else (get_internet_reachable_set(graph) if graph else set())
        has_subnet_data = ctx.has_subnet_data if ctx else (len(infra.vpc.subnets) > 0 if graph else False)

        if graph and has_subnet_data:
            for alb_arn in infra.waf.albs_without_waf:
                # ALB ARN or its short ID might be in the reachable set
                if alb_arn in reachable or alb_arn.split('/')[-1] in reachable:
                    severity = 'Critical'
                    confidence = 'HIGH'
                    attack_path = get_attack_path_to(graph, alb_arn) or get_attack_path_to(graph, alb_arn.split('/')[-1])
                    break

        return RiskFinding(
            rule_id='EMFIRGE-WAF-001',
            category='Security',
            severity=severity,
            raw_severity='Moderate',
            confidence=confidence,
            issue=f'Application Load Balancers without WAF protection: {", ".join(infra.waf.albs_without_waf)}',
            recommendation='Enable AWS WAF on all public-facing Application Load Balancers to protect against common web exploits. Go to WAF & Shield > Web ACLs > Create web ACL > Associate with ALB.',
            aws_service='WAF',
            resource_id=', '.join(infra.waf.albs_without_waf),
            resource_type='application_load_balancer',
            region=infra.region,
            attack_path=attack_path
        )
    return None

# ── ORPHANED RESOURCES ───────────────────────────────────────────

def check_orphaned_resources(infra: AWSInfrastructure, graph: Optional[Graph] = None) -> List[RiskFinding]:
    """
    Detect orphaned resources - resources with no connections to other infrastructure.
    
    These are likely unused resources that are costing money unnecessarily.
    Uses graph analysis to find nodes with zero inbound and zero outbound edges.
    """
    findings = []
    
    if not graph:
        # Cannot detect orphans without graph
        return findings
    
    orphaned = find_orphaned_resources(graph)
    
    for resource in orphaned:
        resource_type = resource['type']
        resource_id = resource['id']
        estimated_cost = resource['estimated_monthly_cost']
        cost_unit = resource['cost_unit']
        
        # Build issue message based on cost
        if estimated_cost > 0:
            issue = f"Orphaned {resource_type}: {resource_id} — no connections to other resources (Est. ${estimated_cost:.2f}/month {cost_unit})"
            recommendation = f"Review if this resource is still needed. If unused, delete it to save ~${estimated_cost:.2f}/month. Orphaned resources have no relationships with other infrastructure."
        else:
            issue = f"Orphaned {resource_type}: {resource_id} — no connections to other resources ({cost_unit})"
            recommendation = f"Review if this resource is still needed. If unused, delete it for better infrastructure hygiene. Orphaned resources have no relationships with other infrastructure."
        
        findings.append(RiskFinding(
            rule_id='EMFIRGE-ORPHAN-001',
            category='Cost',
            severity='Low',
            issue=issue,
            recommendation=recommendation,
            aws_service=_get_service_name(resource_type),
            resource_id=resource_id,
            resource_type=resource_type,
            region=infra.region
        ))
    
    return findings


def _get_service_name(resource_type: str) -> str:
    """Map resource type to AWS service name"""
    type_to_service = {
        'ec2_instance': 'EC2',
        'rds_instance': 'RDS',
        's3_bucket': 'S3',
        'lambda_function': 'Lambda',
        'load_balancer': 'ELB',
        'vpc': 'VPC',
        'vpc_subnet': 'VPC',
        'security_group': 'EC2',
        'iam_role': 'IAM',
        'cloudfront_distribution': 'CloudFront',
    }
    return type_to_service.get(resource_type, 'AWS')


# ── BEST PRACTICES ────────────────────────────────────────────────

def detect_best_practices(infra: AWSInfrastructure) -> List[RiskFinding]:
    best = []

    if infra.ec2.has_load_balancer:
        best.append(RiskFinding(category='Availability', severity='Low',
            issue='Load balancer is configured',
            recommendation='Great! Keep monitoring load balancer health checks',
            aws_service='ELB',
            resource_type='load_balancer', region=infra.region))

    if infra.ec2.auto_scaling_enabled:
        best.append(RiskFinding(category='Availability', severity='Low',
            issue='Auto Scaling is configured',
            recommendation='Great! Make sure scaling policies match your traffic patterns',
            aws_service='EC2',
            resource_type='auto_scaling_group', region=infra.region))

    if len(infra.s3.public_buckets) == 0 and infra.s3.total_buckets > 0:
        best.append(RiskFinding(category='Security', severity='Low',
            issue='All S3 buckets are private',
            recommendation='Great! Keep buckets private and use presigned URLs for sharing',
            aws_service='S3',
            resource_id='all-buckets', resource_type='s3_bucket', region=infra.region))

    if infra.rds.backup_enabled:
        best.append(RiskFinding(category='Disaster Recovery', severity='Low',
            issue='RDS automated backups are enabled',
            recommendation='Great! Consider increasing retention period for better protection',
            aws_service='RDS',
            resource_id=', '.join(infra.rds.instances) if infra.rds.instances else None,
            resource_type='rds_instance', region=infra.region))

    if infra.rds.multi_az_enabled:
        best.append(RiskFinding(category='Availability', severity='Low',
            issue='RDS Multi-AZ is enabled',
            recommendation='Great! Your database will automatically failover if one zone goes down',
            aws_service='RDS',
            resource_type='rds_instance', region=infra.region))

    if not infra.iam.root_has_access_keys:
        best.append(RiskFinding(category='Security', severity='Low',
            issue='Root account has no active access keys',
            recommendation='Great! Keep root access keys deleted',
            aws_service='IAM',
            resource_id='root-account', resource_type='iam_root', region='global'))

    if infra.cloudtrail.is_enabled:
        best.append(RiskFinding(category='Security', severity='Low',
            issue='CloudTrail is enabled',
            recommendation='Great! All AWS account activity is being logged',
            aws_service='CloudTrail',
            resource_id=infra.cloudtrail.trail_arn,
            resource_type='cloudtrail', region=infra.region))

    if infra.cost.has_budget_alerts:
        best.append(RiskFinding(category='Cost', severity='Low',
            issue='AWS Budget alerts are configured',
            recommendation='Great! You will be notified before costs exceed your budget',
            aws_service='Budgets',
            resource_id='aws-budgets', resource_type='budget', region='global'))

    if infra.cloudwatch.has_alarms:
        best.append(RiskFinding(category='Security', severity='Low',
            issue='CloudWatch monitoring is active',
            recommendation='Great! Keep adding more alarms for better coverage',
            aws_service='CloudWatch',
            resource_type='cloudwatch_alarm', region=infra.region))

    if infra.guardduty.is_enabled:
        best.append(RiskFinding(category='Security', severity='Low',
            issue='Amazon GuardDuty is enabled',
            recommendation='Great! Threat detection is active. Review any findings in the GuardDuty console regularly.',
            aws_service='GuardDuty',
            resource_id=infra.guardduty.detector_id,
            resource_type='guardduty_detector', region=infra.region))

    if infra.lambda_data.function_count > 0 and len(infra.lambda_data.functions_with_admin_role) == 0:
        best.append(RiskFinding(category='Security', severity='Low',
            issue='No Lambda functions with admin permissions detected',
            recommendation='Great! Keep Lambda roles scoped to least-privilege permissions.',
            aws_service='Lambda',
            resource_type='lambda_function', region=infra.region))

    if infra.secrets_manager.total_secrets > 0 and len(infra.secrets_manager.secrets_without_rotation) == 0:
        best.append(RiskFinding(category='Security', severity='Low',
            issue='All Secrets Manager secrets have rotation configured',
            recommendation='Great! Keep rotation enabled and review rotation schedules regularly.',
            aws_service='Secrets Manager',
            resource_type='secret', region=infra.region))

    if len(infra.vpc.vpcs_without_flow_logs) == 0 and infra.vpc.total_vpcs > 0:
        best.append(RiskFinding(category='Security', severity='Low',
            issue='VPC Flow Logs are enabled for all VPCs',
            recommendation='Great! Network traffic is being logged for security monitoring.',
            aws_service='VPC',
            resource_type='vpc', region=infra.region))

    if infra.kms.total_cmks > 0 and len(infra.kms.cmks_without_rotation) == 0:
        best.append(RiskFinding(category='Security', severity='Low',
            issue='All KMS customer-managed keys have automatic rotation enabled',
            recommendation='Great! Encryption keys are automatically rotated annually.',
            aws_service='KMS',
            resource_type='kms_key', region=infra.region))

    if infra.config.is_enabled and infra.config.is_recording:
        best.append(RiskFinding(category='Security', severity='Low',
            issue='AWS Config is enabled and recording',
            recommendation='Great! Resource compliance is being monitored.',
            aws_service='Config',
            resource_type='config_recorder', region=infra.region))

    if infra.sns.total_topics > 0 and len(infra.sns.topics_without_encryption) == 0:
        best.append(RiskFinding(category='Security', severity='Low',
            issue='All SNS topics have encryption enabled',
            recommendation='Great! Message data is encrypted at rest.',
            aws_service='SNS',
            resource_type='sns_topic', region=infra.region))

    if infra.ecs.total_task_definitions > 0 and len(infra.ecs.tasks_without_resource_limits) == 0:
        best.append(RiskFinding(category='Security', severity='Low',
            issue='All ECS task definitions have CPU and memory limits configured',
            recommendation='Great! Container resource usage is controlled.',
            aws_service='ECS',
            resource_type='ecs_task_definition', region=infra.region))

    if infra.waf.total_albs > 0 and len(infra.waf.albs_without_waf) == 0:
        best.append(RiskFinding(category='Security', severity='Low',
            issue='All Application Load Balancers have WAF protection enabled',
            recommendation='Great! Web applications are protected by AWS WAF.',
            aws_service='WAF',
            resource_type='application_load_balancer', region=infra.region))

    return best

# ── TOXIC COMBINATIONS ───────────────────────────────────────────

def find_toxic_combos(findings: dict, graph, infrastructure: AWSInfrastructure) -> List[ToxicCombo]:
    """
    Detect dangerous combinations of co-existing findings that are worse together
    than either finding alone.
    """
    combos = []
    critical_risks = findings.get('critical_risks', [])

    # Index critical findings by rule_id for fast lookup
    critical_by_rule: dict = {}
    for f in critical_risks:
        if f.rule_id:
            critical_by_rule.setdefault(f.rule_id, []).append(f)

    # ── COMBO 1: SSH_OPEN_NO_GUARDDUTY ────────────────────────────
    # SSH open to internet AND GuardDuty disabled — brute force with zero detection
    if 'EMFIRGE-EC2-002' in critical_by_rule and not infrastructure.guardduty.is_enabled:
        contributing = critical_by_rule['EMFIRGE-EC2-002']
        resource_ids = [f.resource_id for f in contributing if f.resource_id]
        blast = max((f.blast_radius or 0 for f in contributing), default=0)
        combos.append(ToxicCombo(
            combo_id='SSH_OPEN_NO_GUARDDUTY',
            title='SSH Open to Internet + GuardDuty Disabled',
            description='Attackers can attempt brute force on your servers with zero detection capability.',
            severity='CRITICAL',
            resource_ids=resource_ids,
            contributing_rule_ids=['EMFIRGE-EC2-002'],
            blast_radius=blast,
            attack_path=[]
        ))

    # ── COMBO 2: PUBLIC_RDS_NO_CLOUDTRAIL ─────────────────────────
    # Public RDS AND CloudTrail disabled — database reachable with no audit log
    if 'EMFIRGE-RDS-002' in critical_by_rule and not infrastructure.cloudtrail.is_enabled:
        contributing = critical_by_rule['EMFIRGE-RDS-002']
        resource_ids = [f.resource_id for f in contributing if f.resource_id]
        blast = max((f.blast_radius or 0 for f in contributing), default=0)
        attack_path = contributing[0].attack_path if contributing and contributing[0].attack_path else []
        combos.append(ToxicCombo(
            combo_id='PUBLIC_RDS_NO_CLOUDTRAIL',
            title='Public RDS + CloudTrail Disabled',
            description='Database is reachable from internet with no audit log of who connected or what queries ran.',
            severity='CRITICAL',
            resource_ids=resource_ids,
            contributing_rule_ids=['EMFIRGE-RDS-002'],
            blast_radius=blast,
            attack_path=attack_path
        ))

    # ── COMBO 3: PUBLIC_S3_NO_CLOUDTRAIL ──────────────────────────
    # Any Critical S3-001 finding AND CloudTrail disabled — exposed data, no access record
    s3_critical = [f for f in critical_by_rule.get('EMFIRGE-S3-001', [])]
    if s3_critical and not infrastructure.cloudtrail.is_enabled:
        resource_ids = [f.resource_id for f in s3_critical if f.resource_id]
        blast = max((f.blast_radius or 0 for f in s3_critical), default=0)
        combos.append(ToxicCombo(
            combo_id='PUBLIC_S3_NO_CLOUDTRAIL',
            title='Public S3 Bucket + No Audit Logging',
            description='Data is publicly exposed with no record of who accessed it — a breach would be undetectable.',
            severity='HIGH',
            resource_ids=resource_ids,
            contributing_rule_ids=['EMFIRGE-S3-001'],
            blast_radius=blast,
            attack_path=[]
        ))

    # ── COMBO 4: ROOT_KEYS_ACTIVE_AND_USED ───────────────────────
    # Root access keys exist AND root was used recently — active misuse of highest-privilege creds
    if 'EMFIRGE-IAM-001' in critical_by_rule and infrastructure.iam.root_used_recently:
        contributing = critical_by_rule['EMFIRGE-IAM-001']
        resource_ids = [f.resource_id for f in contributing if f.resource_id]
        blast = max((f.blast_radius or 0 for f in contributing), default=0)
        combos.append(ToxicCombo(
            combo_id='ROOT_KEYS_ACTIVE_AND_USED',
            title='Root Access Keys Active + Root Account Recently Used',
            description='Root credentials are both permanent and actively being used — a leaked key gives an attacker unrestricted access to your entire AWS account with no expiry.',
            severity='CRITICAL',
            resource_ids=resource_ids,
            contributing_rule_ids=['EMFIRGE-IAM-001'],
            blast_radius=blast,
            attack_path=[]
        ))

    # ── COMBO 5: IAM_NO_MFA_OLD_KEYS ─────────────────────────────
    # Any Critical IAM-003 (no MFA) AND any IAM-004 (old keys) — stale creds + no second factor
    iam003_critical = critical_by_rule.get('EMFIRGE-IAM-003', [])
    all_findings_flat = findings.get('critical_risks', []) + findings.get('moderate_risks', []) + findings.get('low_risks', [])
    iam004_findings = [f for f in all_findings_flat if f.rule_id == 'EMFIRGE-IAM-004']
    if iam003_critical and iam004_findings:
        contributing = iam003_critical + iam004_findings
        resource_ids = list({f.resource_id for f in contributing if f.resource_id})
        blast = max((f.blast_radius or 0 for f in contributing), default=0)
        combos.append(ToxicCombo(
            combo_id='IAM_NO_MFA_OLD_KEYS',
            title='IAM Users Without MFA + Expired Access Keys',
            description='Stale credentials with no second factor — a leaked key from any source gives permanent account access with nothing to stop it.',
            severity='CRITICAL',
            resource_ids=resource_ids,
            contributing_rule_ids=['EMFIRGE-IAM-003', 'EMFIRGE-IAM-004'],
            blast_radius=blast,
            attack_path=[]
        ))

    # ── COMBO 6: LAMBDA_ADMIN_NO_CLOUDTRAIL ──────────────────────
    # Lambda with admin role AND CloudTrail disabled — unrestricted serverless access, no audit trail
    if 'EMFIRGE-LAMBDA-001' in critical_by_rule and not infrastructure.cloudtrail.is_enabled:
        contributing = critical_by_rule['EMFIRGE-LAMBDA-001']
        resource_ids = [f.resource_id for f in contributing if f.resource_id]
        blast = max((f.blast_radius or 0 for f in contributing), default=0)
        combos.append(ToxicCombo(
            combo_id='LAMBDA_ADMIN_NO_CLOUDTRAIL',
            title='Lambda with Admin Role + No CloudTrail',
            description='Serverless function has unrestricted AWS access with zero audit trail — an attacker can exfiltrate data or destroy infrastructure leaving no logs.',
            severity='CRITICAL',
            resource_ids=resource_ids,
            contributing_rule_ids=['EMFIRGE-LAMBDA-001'],
            blast_radius=blast,
            attack_path=[]
        ))

    # ── COMBO 7: RDS_NO_BACKUP_NO_DELETION_PROTECTION ────────────
    # RDS no backups AND deletion protection disabled — total data loss with no recovery path
    if 'EMFIRGE-RDS-001' in critical_by_rule and infrastructure.rds.instances_without_deletion_protection:
        rds001 = critical_by_rule['EMFIRGE-RDS-001']
        rds004_findings = [f for f in all_findings_flat if f.rule_id == 'EMFIRGE-RDS-004']
        contributing = rds001 + rds004_findings
        resource_ids = list({f.resource_id for f in contributing if f.resource_id})
        blast = max((f.blast_radius or 0 for f in contributing), default=0)
        combos.append(ToxicCombo(
            combo_id='RDS_NO_BACKUP_NO_DELETION_PROTECTION',
            title='RDS No Backups + Deletion Protection Disabled',
            description='Your database can be permanently deleted with no recovery path — one mistake or malicious action means total data loss.',
            severity='CRITICAL',
            resource_ids=resource_ids,
            contributing_rule_ids=['EMFIRGE-RDS-001', 'EMFIRGE-RDS-004'],
            blast_radius=blast,
            attack_path=[]
        ))

    # ── COMBO 8: PUBLIC_S3_UNENCRYPTED ───────────────────────────
    # Critical public S3 bucket AND unencrypted buckets exist — public plaintext data
    if s3_critical and infrastructure.s3.unencrypted_buckets:
        s3002_findings = [f for f in all_findings_flat if f.rule_id == 'EMFIRGE-S3-002']
        contributing = s3_critical + s3002_findings
        resource_ids = list({f.resource_id for f in contributing if f.resource_id})
        blast = max((f.blast_radius or 0 for f in contributing), default=0)
        combos.append(ToxicCombo(
            combo_id='PUBLIC_S3_UNENCRYPTED',
            title='Public S3 Bucket + No Encryption',
            description='Data is publicly accessible AND stored in plaintext — anyone who finds this bucket gets your raw data with no protection layer.',
            severity='CRITICAL',
            resource_ids=resource_ids,
            contributing_rule_ids=['EMFIRGE-S3-001', 'EMFIRGE-S3-002'],
            blast_radius=blast,
            attack_path=[]
        ))

    # ── COMBO 9: SSH_OPEN_SINGLE_EC2 ─────────────────────────────
    # SSH open to internet AND single EC2 with no load balancer — exposed + no redundancy
    if ('EMFIRGE-EC2-002' in critical_by_rule
            and infrastructure.ec2.instance_count == 1
            and not infrastructure.ec2.has_load_balancer):
        contributing = critical_by_rule['EMFIRGE-EC2-002']
        resource_ids = [f.resource_id for f in contributing if f.resource_id]
        blast = max((f.blast_radius or 0 for f in contributing), default=0)
        combos.append(ToxicCombo(
            combo_id='SSH_OPEN_SINGLE_EC2',
            title='SSH Open to Internet + No Redundancy',
            description='Single exposed server with no load balancer — one successful attack takes down your entire application with no failover.',
            severity='HIGH',
            resource_ids=resource_ids,
            contributing_rule_ids=['EMFIRGE-EC2-002'],
            blast_radius=blast,
            attack_path=[]
        ))

    return combos


# ── NEW AVAILABILITY RULES ────────────────────────────────────────

def check_rds_no_multi_az(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    """RDS without Multi-AZ = database goes down if the AZ has an outage."""
    if infra.rds.instances and not infra.rds.multi_az_enabled:
        return RiskFinding(
            rule_id='EMFIRGE-RDS-006',
            category='Availability',
            severity='Moderate',
            confidence='HIGH',
            issue=f'RDS instance(s) without Multi-AZ: {", ".join(infra.rds.instances)}',
            recommendation='Enable Multi-AZ deployment for automatic failover during AZ outages. Critical for production databases.',
            aws_service='RDS',
            resource_id=', '.join(infra.rds.instances),
            resource_type='rds_instance',
            region=infra.region
        )
    return None


def check_multi_instance_no_alb(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    """Multiple EC2 instances but no load balancer = no traffic distribution or health checks."""
    if infra.ec2.instance_count >= 2 and not infra.ec2.has_load_balancer:
        return RiskFinding(
            rule_id='EMFIRGE-EC2-017',
            category='Availability',
            severity='Moderate',
            confidence='MEDIUM',
            issue=f'{infra.ec2.instance_count} EC2 instances running but no load balancer configured',
            recommendation='Add an Application Load Balancer to distribute traffic and enable health checks across instances.',
            aws_service='EC2',
            resource_type='ec2_instance',
            region=infra.region
        )
    return None


def check_lambda_no_vpc(infra: AWSInfrastructure, graph: Optional[Graph] = None, ctx: Optional['GraphContext'] = None) -> List[RiskFinding]:
    """Lambda functions not in a VPC have no network-level isolation.
    UPGRADED: If Lambda is internet-triggered (reachable) AND has no VPC isolation → Critical.
    If Lambda has admin role AND no VPC isolation → Moderate."""
    findings = []
    # Build set of admin functions for cross-reference
    admin_functions = set(infra.lambda_data.functions_with_admin_role)
    
    # Pre-compute reachability
    reachable = ctx.reachable if ctx else (get_internet_reachable_set(graph) if graph else set())
    has_subnet_data = ctx.has_subnet_data if ctx else (len(infra.vpc.subnets) > 0 if graph else False)

    for fn in infra.lambda_data.functions:
        if not fn.vpc_id:
            severity = 'Low'
            confidence = 'MEDIUM'
            issue_suffix = ''
            attack_path = None

            # If Lambda is internet-reachable AND has no VPC isolation → highest risk
            if has_subnet_data and fn.name in reachable:
                severity = 'Critical'
                confidence = 'HIGH'
                issue_suffix = ' — internet-triggered with no network isolation'
                attack_path = get_attack_path_to(graph, fn.name) if graph else None
            # If this function has an admin role, it's more dangerous without VPC isolation
            elif fn.name in admin_functions:
                severity = 'Moderate'
                confidence = 'HIGH'
                issue_suffix = ' — has admin IAM role (no network isolation + full access)'

            findings.append(RiskFinding(
                rule_id='EMFIRGE-LAMBDA-004',
                category='Availability',
                severity=severity,
                raw_severity='Low',
                confidence=confidence,
                issue=f'Lambda function {fn.name} is not deployed in a VPC{issue_suffix}',
                recommendation='Deploy Lambda functions in a VPC for network isolation and access to private resources. Not required for all functions — evaluate based on what the function accesses.',
                aws_service='Lambda',
                resource_id=fn.name,
                resource_type='lambda_function',
                region=infra.region,
                attack_path=attack_path
            ))
    return findings


def check_single_az_instances(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    """All EC2 instances in the same subnet = single point of failure at the AZ level."""
    if infra.ec2.instance_count < 2:
        return None
    subnet_ids = set()
    for inst in infra.ec2.instances:
        if inst.subnet_id and inst.state == 'running':
            subnet_ids.add(inst.subnet_id)
    # If all running instances are in the same subnet, they're in the same AZ
    if len(subnet_ids) == 1:
        return RiskFinding(
            rule_id='EMFIRGE-EC2-018',
            category='Availability',
            severity='Moderate',
            confidence='MEDIUM',
            issue=f'All {infra.ec2.instance_count} EC2 instances are in the same subnet — single AZ deployment',
            recommendation='Distribute instances across multiple subnets in different Availability Zones for fault tolerance.',
            aws_service='EC2',
            resource_type='ec2_instance',
            region=infra.region
        )
    return None


# ── NEW DISASTER RECOVERY RULES ──────────────────────────────────

def check_rds_low_backup_retention(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    """RDS backup retention under 7 days = limited recovery window."""
    if infra.rds.instances and infra.rds.backup_enabled and infra.rds.backup_retention_days < 7:
        return RiskFinding(
            rule_id='EMFIRGE-RDS-007',
            category='Disaster Recovery',
            severity='Moderate',
            confidence='HIGH',
            issue=f'RDS backup retention is only {infra.rds.backup_retention_days} day(s) — less than recommended 7 days',
            recommendation='Increase backup retention to at least 7 days. For production databases, consider 14-35 days.',
            aws_service='RDS',
            resource_id=', '.join(infra.rds.instances),
            resource_type='rds_instance',
            region=infra.region
        )
    return None


def check_cloudtrail_no_log_validation(infra: AWSInfrastructure) -> Optional[RiskFinding]:
    """CloudTrail without log file validation = logs could be tampered with undetected."""
    if infra.cloudtrail.is_enabled and not infra.cloudtrail.has_log_file_validation:
        return RiskFinding(
            rule_id='EMFIRGE-CT-003',
            category='Disaster Recovery',
            severity='Low',
            confidence='HIGH',
            issue='CloudTrail log file validation is not enabled',
            recommendation='Enable log file validation to detect if CloudTrail logs have been tampered with. Essential for forensics and compliance.',
            aws_service='CloudTrail',
            resource_id=infra.cloudtrail.trail_arn,
            resource_type='cloudtrail',
            region=infra.region
        )
    return None


# ── MAIN FUNCTION ─────────────────────────────────────────────────

def run_all_checks(infrastructure: AWSInfrastructure, graph: Optional[Graph] = None) -> dict:
    critical_risks = []
    moderate_risks = []
    low_risks = []
    cost_findings = []

    # Build graph context once — thread-safe, no globals
    ctx = GraphContext.build(graph, infrastructure)

    # Single-return rules (Optional[RiskFinding])
    # Rules that don't use graph
    all_checks_no_graph = [
        # EC2
        check_no_auto_scaling,
        check_multi_instance_no_alb,
        check_single_az_instances,
        # S3
        check_s3_versioning,
        check_s3_no_logging,
        # RDS
        check_rds_log_exports,
        check_rds_no_multi_az,
        check_rds_low_backup_retention,
        # IAM
        check_root_access_keys,
        check_old_access_keys,
        check_root_used_recently,
        # CloudTrail
        check_cloudtrail_not_multiregion,
        check_cloudtrail_no_log_validation,
        # CloudWatch
        check_no_cloudwatch,
        # GuardDuty
        check_guardduty_disabled,
        # Lambda
        # Secrets Manager
        check_secrets_not_rotated,
        # VPC
        check_vpc_no_flow_logs,
        check_missing_vpc_endpoints,
        # KMS
        check_kms_no_rotation,
        check_kms_pending_deletion,
        # AWS Config
        check_config_disabled,
        check_config_non_compliant,
        # SNS
        check_sns_no_encryption,
        check_sns_public_access,
        # ECS
        check_ecs_no_resource_limits,
        # WAF
    ]
    
    # Rules that use graph (upgraded rules)
    all_checks_with_graph = [
        check_single_ec2_no_alb,
        check_ssh_open,
        check_rdp_open,
        check_rds_public,
        check_rds_no_backup,
        check_rds_encryption,
        check_rds_deletion_protection,
        check_s3_encryption,
        check_cloudtrail_disabled,
        check_default_vpc_in_use,
        check_ecs_privileged_mode,
        check_lambda_admin_role,
        check_lambda_outdated_runtime,
        check_waf_not_enabled,
    ]
    
    # List-return rules without graph (List[RiskFinding])
    list_checks_no_graph = [
        check_users_without_mfa,
        check_lambda_no_vpc,
    ]
    
    # List-return rules with graph (List[RiskFinding])
    list_checks_with_graph = [
        check_public_s3_context_aware,
        check_iam_high_risk_users,
        check_imdsv1_enabled,
        check_dangerous_open_ports,
        check_default_sg_open,
        check_iam_wildcard_policy,
    ]

    # Process single-return rules without graph
    for check in all_checks_no_graph:
        result = check(infrastructure)
        if result:
            if result.severity == 'Critical':
                critical_risks.append(result)
            elif result.severity == 'Moderate':
                moderate_risks.append(result)
            else:
                low_risks.append(result)
    
    # Process single-return rules with graph
    for check in all_checks_with_graph:
        result = check(infrastructure, graph, ctx=ctx)
        if result:
            if result.severity == 'Critical':
                critical_risks.append(result)
            elif result.severity == 'Moderate':
                moderate_risks.append(result)
            else:
                low_risks.append(result)
    
    # Process list-return rules without graph
    for check in list_checks_no_graph:
        results = check(infrastructure, ctx=ctx)
        for result in results:
            if result.severity == 'Critical':
                critical_risks.append(result)
            elif result.severity == 'Moderate':
                moderate_risks.append(result)
            else:
                low_risks.append(result)
    
    # Process list-return rules with graph
    for check in list_checks_with_graph:
        results = check(infrastructure, graph, ctx=ctx)
        for result in results:
            if result.severity == 'Critical':
                critical_risks.append(result)
            elif result.severity == 'Moderate':
                moderate_risks.append(result)
            else:
                low_risks.append(result)

    cost_checks = [
        check_expensive_instance,
        check_stopped_instances,
        check_no_budget_alerts,
        check_no_billing_alarm,
        check_service_dominance,
        # Lambda timeout is a Cost finding — lives here
        check_lambda_timeout,
    ]

    for check in cost_checks:
        result = check(infrastructure)
        if result:
            cost_findings.append(result)
    
    # Orphaned resources check (requires graph)
    if graph:
        orphaned_findings = check_orphaned_resources(infrastructure, graph)
        cost_findings.extend(orphaned_findings)

    best_practices = detect_best_practices(infrastructure)

    return {
        'critical_risks': critical_risks,
        'moderate_risks': moderate_risks,
        'low_risks': low_risks,
        'cost_findings': cost_findings,
        'best_practices': best_practices
    }