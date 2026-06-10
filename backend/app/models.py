from pydantic import BaseModel, Field
from typing import List, Optional, Literal, Union

# -- INPUT MODEL ---------------------------------------------------
class AWSCredentials(BaseModel):
    role_arn: str
    region: str

# -- INFRASTRUCTURE MODELS -----------------------------------------

# Relationship tracking models
class EC2Instance(BaseModel):
    id: str
    type: str
    sg_ids: List[str] = []
    subnet_id: Optional[str] = None
    state: str
    imdsv2_required: bool = False
    instance_profile_arn: Optional[str] = None

class SecurityGroup(BaseModel):
    id: str
    name: str
    rules: List[dict] = []
    attached_to: List[str] = []

class S3Bucket(BaseModel):
    name: str
    is_public: bool = False
    has_cloudfront: bool = False
    policy: Optional[str] = None
    is_empty: bool = False

class RDSInstance(BaseModel):
    id: str
    sg_ids: List[str] = []
    publicly_accessible: bool = False
    encrypted: bool = False

class LambdaFunction(BaseModel):
    name: str
    role_arn: Optional[str] = None
    vpc_id: Optional[str] = None
    subnet_ids: List[str] = []
    secret_refs: List[str] = []

class LoadBalancer(BaseModel):
    arn: str
    type: str
    target_instances: List[str] = []

class EBSVolume(BaseModel):
    id: str
    size_gb: int
    volume_type: str
    create_time: str
    availability_zone: str

class ElasticIP(BaseModel):
    allocation_id: str
    public_ip: str
    is_attached: bool

class VPCSubnet(BaseModel):
    id: str
    vpc_id: str
    resources: List[str] = []
    availability_zone: str = ""
    is_public: bool = False  # True if subnet has a route to an internet gateway

class EC2Data(BaseModel):
    instance_count: int = 0
    instance_types: List[str] = []
    has_load_balancer: bool = False
    auto_scaling_enabled: bool = False
    open_security_groups: List[str] = []
    ssh_open_to_internet: bool = False
    rdp_open_to_internet: bool = False
    stopped_instances: List[str] = []
    free_tier_eligible: bool = True
    instance_ids: List[str] = []
    ssh_security_group_id: Optional[str] = None
    rdp_security_group_id: Optional[str] = None
    # Relationship tracking
    instances: List[EC2Instance] = []
    security_groups: List[SecurityGroup] = []
    load_balancers: List[LoadBalancer] = []
    ebs_volumes: List[EBSVolume] = []
    elastic_ips: List[ElasticIP] = []

class S3Data(BaseModel):
    total_buckets: int = 0
    public_buckets: List[str] = []
    unencrypted_buckets: List[str] = []
    buckets_without_versioning: List[str] = []
    buckets_without_logging: List[str] = []
    # Relationship tracking
    buckets: List[S3Bucket] = []

class RDSData(BaseModel):
    instances: List[str] = []
    multi_az_enabled: bool = False
    backup_enabled: bool = False
    backup_retention_days: int = 0
    publicly_accessible: List[str] = []
    unencrypted_instances: List[str] = []
    instances_without_deletion_protection: List[str] = []
    instances_without_log_exports: List[str] = []
    # Relationship tracking
    rds_instances: List[RDSInstance] = []

class IAMUser(BaseModel):
    username: str
    has_console_access: Optional[bool] = None

class RolePolicy(BaseModel):
    """Parsed IAM role policy data for graph edge creation."""
    role_name: str
    role_arn: str
    accessible_resources: List[str] = []  # Resource ARNs from Allow statements
    has_admin: bool = False               # True if Action:* Resource:*
    policy_names: List[str] = []          # attached/inline policy names (for display)

class IAMData(BaseModel):
    root_has_access_keys: bool = False
    users_without_mfa: List[str] = []
    old_access_keys: List[str] = []
    root_used_recently: bool = False
    users_with_admin_policy: List[str] = []
    # User objects with detailed information
    iam_users: List[IAMUser] = []
    # Role policy data for graph can_access edges
    role_policies: List[RolePolicy] = []

class CloudTrailData(BaseModel):
    is_enabled: bool = False
    is_multi_region: bool = False
    has_log_file_validation: bool = False
    trail_arn: Optional[str] = None

class CostData(BaseModel):
    monthly_cost: float = 0.0
    has_budget_alerts: bool = False
    has_billing_alarm: bool = False
    top_service: str = ''
    top_service_percentage: float = 0.0

class CloudWatchData(BaseModel):
    has_alarms: bool = False
    has_billing_alarm: bool = False

# -- NEW: GUARDDUTY MODEL ------------------------------------------
class GuardDutyData(BaseModel):
    is_enabled: bool = False              # True if at least one active detector exists in the region
    detector_id: Optional[str] = None    # ID of the active detector, if found

# -- NEW: LAMBDA MODEL ---------------------------------------------
class LambdaData(BaseModel):
    function_count: int = 0
    functions_with_admin_role: List[str] = []    # function names with AdministratorAccess or Action:* Resource:*
    functions_with_outdated_runtime: List[str] = []  # function names on deprecated runtimes
    functions_with_no_timeout: List[str] = []    # function names at default 3s or max 900s timeout
    # Relationship tracking
    functions: List[LambdaFunction] = []

# -- NEW: SECRETS MANAGER MODEL ------------------------------------
class SecretsManagerData(BaseModel):
    total_secrets: int = 0
    secrets_without_rotation: List[str] = []     # secret names with rotation disabled or never rotated in 90+ days

# -- NEW: VPC MODEL ------------------------------------------------
class VPCData(BaseModel):
    total_vpcs: int = 0
    vpcs_without_flow_logs: List[str] = []       # VPC IDs without flow logs enabled
    default_vpc_in_use: bool = False
    default_vpc_id: Optional[str] = None
    missing_s3_endpoint: bool = False
    missing_dynamodb_endpoint: bool = False
    # Network topology for reachability
    internet_gateways: List[str] = []            # IGW IDs attached to VPCs
    nat_gateways: List[str] = []                 # NAT gateway IDs
    public_subnet_ids: List[str] = []            # Subnet IDs with route to IGW
    # Relationship tracking
    subnets: List[VPCSubnet] = []

# -- NEW: KMS MODEL ------------------------------------------------
class KMSData(BaseModel):
    total_cmks: int = 0
    cmks_without_rotation: List[str] = []        # Key IDs with rotation disabled
    cmks_pending_deletion: List[str] = []        # Key IDs scheduled for deletion

# -- NEW: AWS CONFIG MODEL -----------------------------------------
class ConfigData(BaseModel):
    is_enabled: bool = False
    is_recording: bool = False
    non_compliant_rules: List[str] = []          # Config rule names with NON_COMPLIANT status

# -- NEW: SNS MODEL ------------------------------------------------
class SNSData(BaseModel):
    total_topics: int = 0
    topics_without_encryption: List[str] = []    # Topic ARNs without KMS encryption
    topics_with_public_access: List[str] = []    # Topic ARNs with Principal: "*" in policy

# -- NEW: ECS MODEL ------------------------------------------------
class ECSData(BaseModel):
    total_task_definitions: int = 0
    tasks_with_privileged_containers: List[str] = []  # Task definition ARNs with privileged=True
    tasks_without_resource_limits: List[str] = []     # Task definition ARNs with missing CPU or memory limits
    task_role_arns: List[str] = []                    # non-empty task role ARNs across all task defs

# -- NEW: WAF MODEL ------------------------------------------------
class WAFData(BaseModel):
    total_albs: int = 0
    albs_without_waf: List[str] = []             # ALB ARNs without an associated WAF Web ACL

# -- NEW: API GATEWAY MODEL ----------------------------------------
class APIGatewayInstance(BaseModel):
    id: str                          # API ID
    name: str
    api_type: str                    # "REST" | "HTTP" | "WEBSOCKET"
    endpoint_type: str               # "REGIONAL" | "EDGE" | "PRIVATE"
    auth_type: str                   # "NONE" | "IAM" | "COGNITO" | "JWT" | "API_KEY"
    has_waf: bool = False
    stage_names: List[str] = []

class APIGatewayData(BaseModel):
    total_apis: int = 0
    apis_without_auth: List[str] = []        # API IDs with no authorization
    apis_without_throttling: List[str] = []  # API IDs with no throttle config
    apis_without_waf: List[str] = []         # API IDs without WAF
    apis: List[APIGatewayInstance] = []

# -- NEW: ELASTICACHE MODEL ----------------------------------------
class ElastiCacheCluster(BaseModel):
    id: str                          # Cluster ID
    engine: str                      # "redis" | "memcached"
    node_type: str                   # e.g. "cache.t3.micro"
    encryption_at_rest: bool = False
    encryption_in_transit: bool = False
    auth_enabled: bool = False       # Redis AUTH token set
    vpc_id: Optional[str] = None
    subnet_group: Optional[str] = None
    sg_ids: List[str] = []

class ElastiCacheData(BaseModel):
    total_clusters: int = 0
    clusters_without_encryption: List[str] = []
    clusters_without_auth: List[str] = []
    clusters_without_transit_encryption: List[str] = []
    clusters: List[ElastiCacheCluster] = []

# -- NEW: SQS MODEL -----------------------------------------------
class SQSQueue(BaseModel):
    url: str
    arn: str
    name: str
    encrypted: bool = False          # KMS encryption enabled
    has_dlq: bool = False            # Dead-letter queue configured
    is_public: bool = False          # Policy allows Principal: "*"

class SQSData(BaseModel):
    total_queues: int = 0
    queues_without_encryption: List[str] = []   # Queue names
    queues_without_dlq: List[str] = []          # Queue names
    queues_with_public_access: List[str] = []   # Queue names
    queues: List[SQSQueue] = []

# -- NEW: DYNAMODB MODEL ------------------------------------------
class DynamoDBTable(BaseModel):
    name: str
    arn: str
    encryption_type: str = "DEFAULT"  # "DEFAULT" | "KMS" | "NONE"
    pitr_enabled: bool = False        # Point-in-time recovery
    has_backup: bool = False          # On-demand backup exists
    billing_mode: str = "PROVISIONED" # "PROVISIONED" | "PAY_PER_REQUEST"
    item_count: int = 0

class DynamoDBData(BaseModel):
    total_tables: int = 0
    tables_without_pitr: List[str] = []         # Table names
    tables_without_encryption: List[str] = []   # Tables using only default encryption
    tables_without_backup: List[str] = []       # No backup plan
    tables: List[DynamoDBTable] = []

# Master infrastructure object - holds all collected data + warnings from skipped services
class AWSInfrastructure(BaseModel):
    ec2: EC2Data = EC2Data()
    s3: S3Data = S3Data()
    rds: RDSData = RDSData()
    iam: IAMData = IAMData()
    cloudtrail: CloudTrailData = CloudTrailData()
    cost: CostData = CostData()
    cloudwatch: CloudWatchData = CloudWatchData()
    guardduty: GuardDutyData = GuardDutyData()
    lambda_data: LambdaData = LambdaData()               # 'lambda' is a Python keyword, so we use lambda_data
    secrets_manager: SecretsManagerData = SecretsManagerData()
    vpc: VPCData = VPCData()                             # NEW
    kms: KMSData = KMSData()                             # NEW
    config: ConfigData = ConfigData()                    # NEW
    sns: SNSData = SNSData()                             # NEW
    ecs: ECSData = ECSData()                             # NEW
    waf: WAFData = WAFData()                             # NEW
    api_gateway: APIGatewayData = APIGatewayData()       # NEW
    elasticache: ElastiCacheData = ElastiCacheData()     # NEW
    sqs: SQSData = SQSData()                             # NEW
    dynamodb: DynamoDBData = DynamoDBData()               # NEW
    region: str = ''
    warnings: List[str] = []          # services skipped due to insufficient permissions

# -- SIMULATION BASELINE MODEL ------------------------------------
class SimulationBaseline(BaseModel):
    public_resource_count: int = 0
    rds_multi_az: bool = False
    rds_instance_count: int = 0
    ec2_instance_count: int = 0
    lambda_function_count: int = 0
    critical_count: int = 0
    moderate_count: int = 0
    maturity_score: int = 0

# -- SIMULATION REQUEST / RESPONSE MODELS -------------------------
class SimulateRequest(BaseModel):
    query: str
    analysis_id: str

class SimulationStage(BaseModel):
    order: int
    caption: str
    node_ids: List[str] = []
    color: str = "red"

class SimulationMetrics(BaseModel):
    user_ceiling: Optional[str] = None
    time_to_failure: Optional[str] = None
    cost_delta: Optional[str] = None

class SimulationRecommendation(BaseModel):
    rank: int
    title: str
    explanation: str
    affected_node_ids: List[str] = []
    fix_available: bool = False
    estimated_cost_delta: Optional[str] = None

class SimulateResponse(BaseModel):
    verdict: str
    severity: str
    summary: str
    stages: List[SimulationStage] = []
    metrics: SimulationMetrics = SimulationMetrics()
    recommendations: List[SimulationRecommendation] = []
    follow_up: Optional[str] = None
    category: str
    query: str

# -- TOXIC COMBO MODEL --------------------------------------------
class ToxicCombo(BaseModel):
    combo_id: str
    title: str
    description: str
    severity: str
    resource_ids: List[str]
    contributing_rule_ids: List[str]
    blast_radius: Optional[int] = 0
    attack_path: Optional[List[str]] = []

# -- FINDING MODEL -------------------------------------------------
class RiskFinding(BaseModel):
    rule_id: Optional[str] = None
    category: str
    severity: str
    raw_severity: Optional[str] = None  # Static severity before graph-aware adjustment (for compliance)
    confidence: str = 'MEDIUM'        # 'HIGH' | 'MEDIUM' | 'LOW' - affects scoring weight
    issue: str
    recommendation: str
    aws_service: str
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    region: Optional[str] = None
    attack_path: Optional[List[str]] = []
    blast_radius: Optional[int] = 0
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None

# -- PRIORITY ACTION MODEL -----------------------------------------
# One item in the AI-generated prioritized action plan (01-05)
# Gemini fills this with specific, resource-aware advice per finding
class PriorityAction(BaseModel):
    rank: str                          # '01', '02', '03', '04', '05'
    title: str                         # short label e.g. 'Close SSH to the internet'
    what_is_wrong: str                 # plain English explanation of the problem
    why_dangerous: str                 # real attacker scenario - what happens if not fixed
    fix_steps: List[str]               # exact AWS console steps to remediate

# -- REMEDIATION INSIGHT MODELS -----------------------------------
class RemediationInsightRequest(BaseModel):
    rule_id: Optional[str] = None
    severity: str
    issue: str
    recommendation: str
    resource_id: Optional[str] = None
    region: Optional[str] = None
    aws_service: str
    attack_path: Optional[List[str]] = []
    account_id: Optional[str] = None

class RemediationInsightResponse(BaseModel):
    what_this_fixes: str
    why_it_matters: str

# -- RESPONSE MODEL ------------------------------------------------
class AnalysisResponse(BaseModel):
    analysis_id: str
    timestamp: str
    region_analyzed: str

    overall_risk_score: int
    overall_risk_level: str

    security_score: int
    availability_score: int
    disaster_recovery_score: int

    cost_score: int
    cost_level: str

    maturity_score: int = 0
    maturity_bonus: float = 0.0
    maturity_checks_passed: List[str] = []
    simulation_baseline: Optional[SimulationBaseline] = None

    critical_risks: List[RiskFinding]
    moderate_risks: List[RiskFinding]
    best_practices: List[RiskFinding]
    cost_findings: List[RiskFinding]
    toxic_combinations: List[ToxicCombo] = []

    ai_summary: str
    recommended_improvements: List[str]
    priority_actions: List[PriorityAction] = []   # AI advisor action plan

    warnings: List[str] = []          # services skipped due to insufficient permissions

    total_resources_scanned: int
    scan_duration_seconds: float
    report_url: str

# -- TERRAFORM MODELS ----------------------------------------------
class TerraformGenerateRequest(BaseModel):
    rule_id: Optional[str] = None
    severity: str
    issue: str
    recommendation: str
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    region: Optional[str] = None
    aws_service: str
    attack_path: Optional[List[str]] = []
    blast_radius: Optional[int] = 0
    account_id: Optional[str] = None
    analysis_id: Optional[str] = None

class TerraformGenerateResponse(BaseModel):
    hcl: str
    filename: str
    valid: Optional[bool] = None
    errors: Optional[str] = None

# -- GITHUB PR MODELS ----------------------------------------------
class GitHubPRRequest(BaseModel):
    installation_id: int
    repo: str
    finding: dict
    hcl: str

class GitHubPRResponse(BaseModel):
    pr_url: str
    pr_number: int
    branch: str

class GitHubReposResponse(BaseModel):
    repos: List[str]


class FeedbackRequest(BaseModel):
    message: str
    name: Optional[str] = ''
    email: Optional[str] = ''
    page: Optional[str] = ''
    aws_account_id: Optional[str] = ''


# -- COMPONENT SIMULATION MODELS -----------------------------------
# Discriminated union configs for POST /simulate/component

class EC2Config(BaseModel):
    component_type: Literal["ec2_instance"] = "ec2_instance"
    instance_type: str = "t3.micro"
    public_ip: bool = False
    sg_ids: List[str] = []
    subnet_id: str = ""
    imdsv2_required: bool = True

class RDSConfig(BaseModel):
    component_type: Literal["rds_instance"] = "rds_instance"
    engine: str = "postgres"
    publicly_accessible: bool = False
    encrypted: bool = True
    multi_az: bool = False
    subnet_id: str = ""
    sg_ids: List[str] = []
    deletion_protection: bool = False

class S3Config(BaseModel):
    component_type: Literal["s3_bucket"] = "s3_bucket"
    is_public: bool = False
    encrypted: bool = True
    versioning: bool = True
    has_cloudfront: bool = False

class LambdaConfig(BaseModel):
    component_type: Literal["lambda_function"] = "lambda_function"
    in_vpc: bool = False
    subnet_ids: List[str] = []
    role_type: Literal["least_privilege", "admin"] = "least_privilege"
    timeout: int = 30
    runtime: str = "python3.11"

class ALBConfig(BaseModel):
    component_type: Literal["load_balancer"] = "load_balancer"
    lb_type: Literal["ALB", "NLB"] = "ALB"
    https_only: bool = True
    waf_attached: bool = False
    target_instance_ids: List[str] = []

class APIGatewayConfig(BaseModel):
    component_type: Literal["api_gateway"] = "api_gateway"
    gw_type: Literal["REST", "HTTP"] = "HTTP"
    auth: Literal["none", "iam", "cognito"] = "none"
    is_public: bool = True
    waf_attached: bool = False

class ElastiCacheConfig(BaseModel):
    component_type: Literal["elasticache"] = "elasticache"
    engine: Literal["redis", "memcached"] = "redis"
    in_vpc: bool = True
    encryption_in_transit: bool = True
    auth_enabled: bool = True

class ECSConfig(BaseModel):
    component_type: Literal["ecs_service"] = "ecs_service"
    launch_type: Literal["FARGATE", "EC2"] = "FARGATE"
    privileged: bool = False
    resource_limits: bool = True
    public_ip: bool = False

class SGRuleConfig(BaseModel):
    component_type: Literal["sg_rule"] = "sg_rule"
    sg_id: str
    action: Literal["add", "remove"] = "add"
    port: int = 443
    protocol: Literal["tcp", "udp"] = "tcp"
    source: str = "0.0.0.0/0"

class IAMPolicyConfig(BaseModel):
    component_type: Literal["iam_policy"] = "iam_policy"
    role_name: str
    action: Literal["attach", "detach"] = "attach"
    policy_name: str = ""

# Discriminated union for the component request
ComponentConfig = Union[
    EC2Config, RDSConfig, S3Config, LambdaConfig, ALBConfig,
    APIGatewayConfig, ElastiCacheConfig, ECSConfig, SGRuleConfig, IAMPolicyConfig
]

class ComponentRequest(BaseModel):
    config: ComponentConfig = Field(discriminator="component_type")
    analysis_id: str

class ComponentResponse(BaseModel):
    new_node: Optional[dict] = None
    new_edges: List[dict] = []
    new_findings: List[dict] = []
    new_toxic_combos: List[dict] = []
    attack_paths: List[dict] = []
    narrative: dict = {}
    risk_delta: dict = {}


# -- VERIFY FIX MODELS ---------------------------------------------
class VerifyFixRequest(BaseModel):
    analysis_id: str
    rule_id: str
    resource_id: str

class VerifyFixResponse(BaseModel):
    can_simulate: bool
    findings_removed: List[dict] = []
    findings_added: List[dict] = []
    toxic_combos_resolved: List[str] = []
    toxic_combos_created: List[str] = []
    score_before: int = 0
    score_after: int = 0
    score_delta: int = 0
    safe_to_apply: bool = True


# -- TF INDEX MODELS -----------------------------------------------
class TFIndexRequest(BaseModel):
    installation_id: int
    repo: str

class TFIndexResponse(BaseModel):
    status: str             # "indexed" | "error"
    resources_found: int = 0
    repo: str = ""
    message: str = ""

class TFIndexStatusResponse(BaseModel):
    indexed: bool
    count: int = 0
    last_indexed: Optional[str] = None
    repo: str = ""


# -- CI/CD GATE MODELS --------------------------------------------
class CIAnalyzeRequest(BaseModel):
    """Request body for CI/CD security analysis of a PR."""
    repo: str                           # e.g. "org/repo"
    pr_number: int
    base_ref: str = "main"              # branch being merged into
    head_ref: str = ""                  # branch being merged
    analysis_id: Optional[str] = None   # last scan to simulate against

class CIAnalyzeResponse(BaseModel):
    """Response from CI/CD security analysis."""
    status: str                         # "pass" | "fail" | "warn" | "skip"
    score_delta: int = 0
    new_findings: List[dict] = []
    resolved_findings: List[dict] = []
    new_toxic_combos: List[str] = []
    summary: str = ""
    scan_age_hours: Optional[float] = None

class CIAPIKeyRequest(BaseModel):
    installation_id: int
    repo: str

class CIAPIKeyResponse(BaseModel):
    api_key: str
    repo: str
    message: str = ""
