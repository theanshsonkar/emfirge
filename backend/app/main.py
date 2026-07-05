from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware  # NEW
from fastapi.responses import StreamingResponse
from botocore.exceptions import ClientError, NoCredentialsError
from typing import Optional
import boto3
import os
import time
import uuid
import json
import subprocess
import tempfile
import logging
from datetime import datetime, date
from collections import defaultdict
from dotenv import load_dotenv

# AGENTOPS IMPORT
# (AgentOps telemetry omitted from public source)

from app.models import (
    AWSCredentials, AnalysisResponse,
    RemediationInsightRequest, RemediationInsightResponse,
    TerraformGenerateRequest, TerraformGenerateResponse,
    GitHubPRRequest, GitHubPRResponse, GitHubReposResponse,
    SimulateRequest, SimulateResponse, SimulationStage, SimulationMetrics, SimulationRecommendation,
    FeedbackRequest,
    ComponentRequest, ComponentResponse, AWSInfrastructure,
    VerifyFixRequest, VerifyFixResponse,
    TFIndexRequest, TFIndexResponse, TFIndexStatusResponse,
    CIAnalyzeRequest, CIAnalyzeResponse, CIAPIKeyRequest, CIAPIKeyResponse,
)
from app.aws_collector import collect_infrastructure
from app.rules import run_all_checks, find_toxic_combos
from app.scoring import calculate_score
from app.llm import generate_explanation
from app.database import create_tables, save_analysis, get_recent_logs, get_log_by_id, get_scan_count_today, get_previous_scan_for_account, save_drift_events, get_drift_events, save_simulation_log, get_simulation_count_today, save_feedback, get_feedback, save_llm_usage, get_llm_usage_count_today, save_tf_index, get_tf_index, get_tf_index_status, create_ci_api_key, validate_ci_api_key, get_ci_api_keys
from app.storage import save_report, get_report_url
from app.egraph import build_graph, get_simulation_slice, validate_simulation_response, classify_query, format_graph_for_claude, bfs_from_internet, find_attack_path, Graph
from app.drift_service import compare_findings
from app.compliance import evaluate_all_frameworks

load_dotenv()

logger = logging.getLogger(__name__)

# Create database tables when app starts
create_tables()

# ── IN-MEMORY RATE LIMITER FOR INSIGHT ENDPOINT ───────────────────
# Tracks (ip → list of request timestamps) for a sliding 60-second window.
# No external dependency — resets on server restart, which is acceptable
# for a lightweight Gemini cost guard.
_insight_request_log: dict = defaultdict(list)
_INSIGHT_LIMIT = 5       # max requests
_INSIGHT_WINDOW = 60     # seconds

def _check_insight_rate_limit(ip: str) -> None:
    """Raises HTTP 429 if the IP has exceeded 5 requests in the last 60 seconds."""
    now = time.time()
    window_start = now - _INSIGHT_WINDOW
    # Prune timestamps outside the window
    _insight_request_log[ip] = [t for t in _insight_request_log[ip] if t > window_start]
    if len(_insight_request_log[ip]) >= _INSIGHT_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f'Rate limit reached. You can generate {_INSIGHT_LIMIT} AI insights per minute. Please wait a moment and try again.'
        )
    _insight_request_log[ip].append(now)

# ── IN-MEMORY RATE LIMITER FOR TERRAFORM + PR ENDPOINTS ──────────
_terraform_request_log: dict = defaultdict(list)
_TERRAFORM_LIMIT = 5
_TERRAFORM_WINDOW = 60

_pr_request_log: dict = defaultdict(list)
_PR_LIMIT = 10
_PR_WINDOW = 60

# ── IN-MEMORY RATE LIMITER FOR SIMULATE ENDPOINT ─────────────────
_simulate_request_log: dict = {}

def _check_terraform_rate_limit(ip: str) -> None:
    """Raises HTTP 429 if the IP has exceeded 5 terraform requests in the last 60 seconds."""
    now = time.time()
    window_start = now - _TERRAFORM_WINDOW
    _terraform_request_log[ip] = [t for t in _terraform_request_log[ip] if t > window_start]
    if len(_terraform_request_log[ip]) >= _TERRAFORM_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f'Rate limit reached. You can generate {_TERRAFORM_LIMIT} Terraform fixes per minute. Please wait a moment and try again.'
        )
    _terraform_request_log[ip].append(now)

def _check_pr_rate_limit(ip: str) -> None:
    """Raises HTTP 429 if the IP has exceeded 10 PR requests in the last 60 seconds."""
    now = time.time()
    window_start = now - _PR_WINDOW
    _pr_request_log[ip] = [t for t in _pr_request_log[ip] if t > window_start]
    if len(_pr_request_log[ip]) >= _PR_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f'Rate limit reached. You can open {_PR_LIMIT} PRs per minute. Please wait a moment and try again.'
        )
    _pr_request_log[ip].append(now)


def _lookup_resource_name(resource_id: str, resource_type: str) -> Optional[str]:
    """
    Look up a resource's human-readable name from the most recent scan data.
    E.g. SG ID "sg-0a1b2c3d4e5f00002" → name "ssh-open-sg"
    Falls back to None if not found.
    """
    try:
        recent = get_recent_logs(limit=1)
        if not recent:
            return None
        log = get_log_by_id(recent[0]['id'])
        if not log or not log.get('findings_json'):
            return None
        findings_data = json.loads(log['findings_json']) if isinstance(log['findings_json'], str) else log['findings_json']
        infra = findings_data.get('infrastructure', {})

        # Security groups: match by ID, return name
        if resource_type in ('security_group', '') and resource_id.startswith('sg-'):
            for sg in infra.get('ec2', {}).get('security_groups', []):
                sg_id = sg.get('id', '') if isinstance(sg, dict) else getattr(sg, 'id', '')
                if sg_id == resource_id:
                    return sg.get('name', '') if isinstance(sg, dict) else getattr(sg, 'name', '')

        # RDS: match by ID, return identifier (usually same)
        if resource_type in ('rds_instance', ''):
            for rds in infra.get('rds', {}).get('rds_instances', []):
                rds_id = rds.get('id', '') if isinstance(rds, dict) else getattr(rds, 'id', '')
                if rds_id == resource_id:
                    return rds_id  # RDS identifier IS the name

        # EC2: match by instance ID, return Name tag (if available)
        if resource_type in ('ec2_instance', '') and resource_id.startswith('i-'):
            for inst in infra.get('ec2', {}).get('instances', []):
                inst_id = inst.get('id', '') if isinstance(inst, dict) else getattr(inst, 'id', '')
                if inst_id == resource_id:
                    # No name field on instances in our model, return None
                    return None

        # S3: bucket name IS the resource_id in our system, so no lookup needed
        return None
    except Exception as e:
        print(f"[_lookup_resource_name] Error: {e}")
        return None

# AGENTOPS INIT — runs once when server starts
try:
    pass  # AgentOps init omitted from public source
except Exception as _agentops_err:
    logger.warning(f'AgentOps init failed (non-fatal): {_agentops_err}')


# Raw mode = caller is an LLM host (MCP, etc.) so we skip Gemini/Claude calls.
# The host renders the response itself, no need to spend tokens here.
def _is_raw_mode(request: Request, raw: bool = False) -> bool:
    if raw:
        return True
    if request and request.headers.get('x-mcp', '').lower() in ('1', 'true', 'yes'):
        return True
    if request and request.headers.get('x-source', '').lower() == 'mcp':
        return True
    return False


# Daily scan cap per AWS account. Overridable via DAILY_SCAN_LIMIT env var.
DAILY_SCAN_LIMIT = int(os.getenv('DAILY_SCAN_LIMIT', '5'))


app = FastAPI(title='AWS Risk Analysis Agent', version='2.0')

# ── CORS ──────────────────────────────────────────────────────────
# Allows the browser to call this API from Vercel and localhost
# Without this, every fetch() from the frontend gets blocked silently
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://emfirge.vercel.app",   # Production frontend
        "http://localhost:*",            # All localhost ports for local dev
        "http://127.0.0.1:*",            # Alternative localhost
    ],
    allow_origin_regex=r"http://localhost:\d+|http://127\.0\.0\.1:\d+",  # Regex for any localhost port
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],  # All HTTP methods
    allow_headers=["*"],  # All headers
    allow_credentials=True,  # Allow cookies/auth headers
)

@app.get('/')
def home():
    return {'message': 'AWS Risk Agent is running', 'status': 'ok', 'version': '2.0'}

@app.get('/health')
def health():
    db_ok = True
    try:
        from app.database import SessionLocal
        from sqlalchemy import text
        session = SessionLocal()
        session.execute(text('SELECT 1'))
        session.close()
    except Exception:
        db_ok = False
    return {'status': 'healthy' if db_ok else 'degraded', 'db': 'ok' if db_ok else 'unreachable'}

@app.get('/logs')
def logs(account_id: str = None):
    recent_logs = get_recent_logs(limit=20, account_id=account_id)
    return {'logs': recent_logs, 'count': len(recent_logs)}

@app.get('/history')
def history(limit: int = 10, account_id: str = None):
    logs = get_recent_logs(limit=limit, account_id=account_id)
    # Calculate score delta vs previous scan
    enriched = []
    for i, log in enumerate(logs):
        delta = None
        if i < len(logs) - 1:
            delta = log['risk_score'] - logs[i + 1]['risk_score']
        enriched.append({
            **log,
            'score_delta': delta,
            'trend': 'improved' if delta and delta < 0 else 'regressed' if delta and delta > 0 else 'unchanged'
        })
    return {'scans': enriched, 'count': len(enriched)}

@app.get('/drift/events')
def drift_events_endpoint(account_id: str = None, limit: int = 20):
    events = get_drift_events(account_id=account_id, limit=limit)
    return {'events': events, 'count': len(events)}

@app.get('/logs/{log_id}')
def get_log(log_id: int, account_id: str = None):
    log = get_log_by_id(log_id, account_id=account_id)
    if not log:
        raise HTTPException(status_code=404, detail='Log not found')
    return log

@app.get('/logs/by-uuid/{analysis_id}')
def get_log_by_uuid(analysis_id: str, account_id: str = None):
    """
    Fetch a scan record by analysis_id (UUID). Used by MCP clients that
    only know the UUID, not the integer DB id.

    Mirrors the lookup pattern used by /egraph/{analysis_id}: validate
    the UUID format, then run a LIKE query on findings_json.
    """
    import re
    if not re.match(r'^[a-zA-Z0-9\-]+$', analysis_id):
        raise HTTPException(status_code=400, detail='Invalid analysis_id format')

    from app.database import SessionLocal, AnalysisLog
    session = SessionLocal()
    try:
        target = session.query(AnalysisLog.id).filter(
            AnalysisLog.findings_json.like(f'%"analysis_id": "{analysis_id}"%')
        ).order_by(AnalysisLog.timestamp.desc()).first()
        if not target:
            raise HTTPException(status_code=404, detail=f'Analysis {analysis_id} not found')
        log = get_log_by_id(target.id, account_id=account_id)
        if not log:
            raise HTTPException(status_code=404, detail='Log not found')
        return log
    finally:
        session.close()

@app.get('/egraph/{analysis_id}')
def get_graph(analysis_id: str):
    """
    Get infrastructure graph data for a completed scan.
    
    Returns infrastructure graph with nodes, edges, orphaned resources, and statistics.
    """
    import re
    # Validate analysis_id format (UUID or demo prefix) to prevent LIKE pattern abuse
    if not re.match(r'^[a-zA-Z0-9\-]+$', analysis_id):
        raise HTTPException(status_code=400, detail='Invalid analysis_id format')
    
    from app.egraph import find_orphaned_resources
    from collections import Counter
    import json
    
    # Get analysis from database by searching for analysis_id in findings_json
    # Since analysis_id is stored in the JSON, we need to search for it
    from app.database import SessionLocal, AnalysisLog
    
    session = SessionLocal()
    try:
        # Filter by analysis_id string inside findings_json at the DB level
        # This avoids fetching and deserializing all 100 rows in Python
        target_log = session.query(AnalysisLog).filter(
            AnalysisLog.findings_json.like(f'%"analysis_id": "{analysis_id}"%')
        ).order_by(AnalysisLog.timestamp.desc()).first()

        if not target_log:
            raise HTTPException(status_code=404, detail=f'Analysis {analysis_id} not found')
        
        # Parse the stored findings_json
        findings_data = json.loads(target_log.findings_json)
        
        # Check if infrastructure data was stored (it won't be in older scans)
        if 'infrastructure' not in findings_data:
            return {
                'error': 'Infrastructure data not available',
                'message': 'This scan was performed before infrastructure data storage was implemented. Please run a new scan to get graph data.',
                'analysis_id': analysis_id,
                'timestamp': findings_data.get('timestamp'),
                'region': findings_data.get('region_analyzed')
            }
        
        # Reconstruct infrastructure from stored data
        from app.models import AWSInfrastructure
        infra_dict = findings_data['infrastructure']
        infrastructure = AWSInfrastructure(**infra_dict)
        
        # Build graph
        graph = build_graph(infrastructure)
        
        # Find orphaned resources
        orphaned = find_orphaned_resources(graph)
        
        # Aggregate attack paths from findings
        # Include findings with non-empty attack_path OR blast_radius > 0
        # (mirrors Findings page behavior — blast_radius > 0 means lateral movement is possible)
        all_findings = (
            findings_data.get('critical_risks', []) +
            findings_data.get('moderate_risks', [])
        )
        seen_paths = set()
        attack_paths = []
        for f in all_findings:
            path = f.get('attack_path', [])
            blast = f.get('blast_radius', 0) or 0
            # Skip findings with no path AND no blast radius
            if not path and blast == 0:
                continue
            # If no traversal path but blast_radius > 0, use resource_id as the path
            if not path and f.get('resource_id'):
                path = [f['resource_id']]
            if not path:
                continue
            path_key = tuple(path)
            if path_key in seen_paths:
                continue
            seen_paths.add(path_key)
            attack_paths.append({
                'finding_id': f.get('rule_id', ''),
                'finding_title': f.get('issue', ''),
                'severity': (f.get('severity') or 'low').lower(),
                'path': path,
            })

        # Build node label lookup for path rendering
        node_label_map = {n['id']: n.get('label', n['id']) for n in graph.nodes}

        # Find critical resources (nodes most referenced in attack paths)
        from app.egraph import find_critical_resources, dijkstra_from_internet, betweenness_centrality
        critical_resources = find_critical_resources(graph, all_findings)

        # Dijkstra weighted paths + betweenness centrality (chokepoint analysis)
        dijkstra_result = dijkstra_from_internet(graph)
        centrality_scores = betweenness_centrality(graph)

        # Enrich critical_resources with centrality and exploit distance
        for cr in critical_resources:
            cr['centrality'] = round(centrality_scores.get(cr['node_id'], 0.0), 6)
            dijk = dijkstra_result.get(cr['node_id'])
            cr['exploit_distance'] = dijk['distance'] if dijk else None

        # Calculate statistics
        node_types = Counter(node['type'] for node in graph.nodes)
        edge_types = Counter(edge['relationship'] for edge in graph.edges)
        total_waste = sum(r['estimated_monthly_cost'] for r in orphaned)
        
        # Return graph data
        return {
            'analysis_id': analysis_id,
            'timestamp': findings_data.get('timestamp'),
            'region': findings_data.get('region_analyzed'),
            'nodes': graph.nodes,
            'edges': graph.edges,
            'orphaned_resources': orphaned,
            'attack_paths': attack_paths,
            'node_label_map': node_label_map,
            'critical_resources': critical_resources,
            'dijkstra_distances': dijkstra_result,
            'centrality_scores': centrality_scores,
            'stats': {
                'total_nodes': len(graph.nodes),
                'total_edges': len(graph.edges),
                'orphaned_count': len(orphaned),
                'estimated_monthly_waste': round(total_waste, 2),
                'node_types': dict(node_types),
                'edge_types': dict(edge_types)
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'Error retrieving graph data: {str(e)}')
    finally:
        session.close()


@app.get('/compliance/{analysis_id}')
def get_compliance(analysis_id: str):
    """
    Evaluate compliance frameworks (CIS AWS 1.5, SOC 2) against a completed scan.

    For each control, checks if the mapped EMFIRGE rule fired in the scan findings.
    Rule fired → control FAIL. Rule not fired → control PASS.
    Returns pass/fail per control + overall percentages for each framework.
    """
    import re

    # Validate analysis_id format
    if not re.match(r'^[a-zA-Z0-9\-]+$', analysis_id):
        raise HTTPException(status_code=400, detail='Invalid analysis_id format')

    from app.database import SessionLocal, AnalysisLog

    session = SessionLocal()
    try:
        # Find the analysis by analysis_id in findings_json
        target_log = session.query(AnalysisLog).filter(
            AnalysisLog.findings_json.like(f'%"analysis_id": "{analysis_id}"%')
        ).order_by(AnalysisLog.timestamp.desc()).first()

        if not target_log:
            raise HTTPException(status_code=404, detail=f'Analysis {analysis_id} not found')

        # Parse findings_json
        findings_data = json.loads(target_log.findings_json)

        # Collect all fired rule_ids from all finding categories
        # Include low_risks to catch graph-aware downgraded findings (compliance checks rule presence, not severity)
        fired_rule_ids = set()
        for category in ['critical_risks', 'moderate_risks', 'low_risks', 'best_practices', 'cost_findings']:
            for finding in findings_data.get(category, []):
                rule_id = finding.get('rule_id')
                if rule_id:
                    fired_rule_ids.add(rule_id)

        # Get infrastructure dict for N/A determination
        infrastructure = findings_data.get('infrastructure')

        # Evaluate all frameworks
        frameworks = evaluate_all_frameworks(fired_rule_ids, infrastructure)

        return {
            'analysis_id': analysis_id,
            'timestamp': findings_data.get('timestamp'),
            'frameworks': frameworks,
            'fired_rule_ids': sorted(fired_rule_ids),
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'Error evaluating compliance: {str(e)}')
    finally:
        session.close()


@app.post("/simulate")
async def simulate(request: SimulateRequest, http_request: Request, raw: bool = False):
    """
    Single-phase SSE simulation: Haiku for narrative + deterministic BFS for attack chain.
    Fast (~2-4s), reliable, cheap. No Sonnet needed.
    Rate limited to 10 requests/minute per IP.
    """
    # ── RATE LIMIT: 10/min per IP ─────────────────────────────────
    client_ip = http_request.client.host if http_request.client else 'unknown'
    now = time.time()
    _simulate_request_log.setdefault(client_ip, [])
    _simulate_request_log[client_ip] = [t for t in _simulate_request_log[client_ip] if now - t < 60]
    if len(_simulate_request_log[client_ip]) >= 10:
        raise HTTPException(status_code=429, detail='Rate limit exceeded. You can run 10 simulations per minute.')
    _simulate_request_log[client_ip].append(now)

    # ── LOAD INFRASTRUCTURE FROM DB ───────────────────────────────
    from app.database import SessionLocal, AnalysisLog
    from app.models import AWSInfrastructure

    infrastructure = None
    baseline = None
    aws_account_id = None
    try:
        session = SessionLocal()
        try:
            logs = session.query(AnalysisLog).order_by(AnalysisLog.timestamp.desc()).limit(100).all()
            for log in logs:
                try:
                    data = json.loads(log.findings_json)
                    if data.get('analysis_id') == request.analysis_id:
                        infra_dict = data.get('infrastructure', {})
                        infrastructure = AWSInfrastructure(**infra_dict)
                        baseline = data.get('simulation_baseline')
                        aws_account_id = log.aws_account_id or None
                        break
                except Exception:
                    continue
        finally:
            session.close()
    except Exception as e:
        logger.error(f"simulate: DB load failed: {e}")

    if not infrastructure:
        async def error_stream():
            payload = {
                "verdict": "Scan data not found for this analysis ID.",
                "severity": "low",
                "summary": "No infrastructure data was found for the provided analysis_id. Please run a new scan first.",
                "stages": [],
                "blast_radius": {"total": 0, "by_type": {}},
                "follow_up": "Run a new scan to analyze your infrastructure.",
                "category": "general",
                "query": request.query,
            }
            yield f"event: preview\ndata: {json.dumps({'verdict': payload['verdict'], 'severity': payload['severity'], 'summary': payload['summary']})}\n\n"
            yield f"event: complete\ndata: {json.dumps(payload)}\n\n"
        return StreamingResponse(error_stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    # ── DAILY SIMULATION LIMIT: 10/day per AWS account ─────────────
    SIMULATION_DAILY_LIMIT = 10
    WHITELISTED_ACCOUNTS = set(filter(None, os.getenv('WHITELISTED_ACCOUNTS', '').split(',')))
    if aws_account_id and aws_account_id not in WHITELISTED_ACCOUNTS:
        sim_count = get_simulation_count_today(aws_account_id)
        if sim_count >= SIMULATION_DAILY_LIMIT:
            raise HTTPException(
                status_code=429,
                detail=f'Simulation limit reached. Your account has used {sim_count}/{SIMULATION_DAILY_LIMIT} simulations today. Resets at midnight UTC.'
            )

    # ── META-QUERY CHECK (skip LLM entirely) ─────────────────────
    _META_PHRASES = ['real infra', 'real data', 'actually scanning', 'live scan',
                     'real account', 'really scanning', 'real aws']
    if any(p in request.query.lower() for p in _META_PHRASES):
        _meta_response = {
            "verdict": "Yes — this is your real AWS infrastructure, scanned minutes ago via IAM role assumption.",
            "severity": "low",
            "summary": (
                "Emfirge assumed your IAM role, called live AWS APIs, and built the graph you see from the actual "
                "response. The security groups, EC2 instances, subnets, and edges are real resources in your "
                "account — not demo data."
            ),
            "stages": [],
            "blast_radius": {"total": 0, "by_type": {}},
            "follow_up": "What can an attacker reach from the internet in my current setup?",
            "category": "general",
            "query": request.query,
        }
        async def meta_stream():
            yield f"event: preview\ndata: {json.dumps({'verdict': _meta_response['verdict'], 'severity': _meta_response['severity'], 'summary': _meta_response['summary']})}\n\n"
            yield f"event: complete\ndata: {json.dumps(_meta_response)}\n\n"
        return StreamingResponse(meta_stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    # ── BUILD GRAPH + CLASSIFY + SLICE ────────────────────────────
    graph = build_graph(infrastructure)
    category = classify_query(request.query)
    slice_dict = get_simulation_slice(graph, category)
    graph_text = format_graph_for_claude(slice_dict)
    layers = slice_dict.get('layers', {})

    # ── DETERMINISTIC: Build attack chain from BFS ────────────────
    def _build_attack_stages(slice_data: dict, graph_obj: Graph) -> list:
        """Build attack chain stages from BFS layers with narrative captions."""
        bfs_layers = slice_data.get('layers', {})
        if not bfs_layers:
            return []

        # Build a shortest-path tree: for each node, find the edge that brought it into BFS
        # This lets us describe HOW the attacker moves, not just WHERE
        parent_edge: dict = {}  # node_id -> edge dict that discovered it
        for edge in graph_obj.edges:
            src, tgt = edge['from'], edge['to']
            if src in bfs_layers and tgt in bfs_layers:
                src_depth = bfs_layers[src]
                tgt_depth = bfs_layers[tgt]
                if tgt_depth == src_depth + 1 and tgt not in parent_edge:
                    parent_edge[tgt] = edge

        # Narrative templates based on edge relationship + node type
        def _caption_for_edge(edge: dict, target_node: dict) -> str:
            rel = edge.get('relationship', '')
            target_label = target_node.get('label', target_node['id'])
            target_type = target_node.get('type', '')
            source_node = graph_obj.get_node(edge['from'])
            source_label = source_node.get('label', edge['from']) if source_node else edge['from']

            if rel == 'REACHES' and target_type == 'security_group':
                return f"Internet reaches {target_label} — open inbound rules"
            if rel == 'REACHES' and target_type == 'api_gateway':
                return f"Internet reaches API Gateway {target_label}"
            if rel == 'REACHES_VIA_SG':
                return f"Attacker lands on {target_label} via open security group"
            if rel == 'REACHES':
                return f"Internet directly reaches {target_label}"
            if rel == 'attached_to_instance':
                return f"Security group exposes {target_label} to network"
            if rel == 'uses_iam_role':
                return f"{source_label} assumes {target_label} — credential theft possible"
            if rel == 'can_access':
                return f"IAM role accesses {target_label} — data exfiltration risk"
            if rel == 'uses_security_group':
                return f"{source_label} shares network access via {target_label}"
            if rel == 'in_subnet':
                return f"{source_label} is in {target_label} — lateral movement"
            if rel == 'targets_instance':
                return f"Load balancer routes traffic to {target_label}"
            if rel == 'contains_resource':
                return f"Subnet contains {target_label}"
            if rel == 'belongs_to_vpc':
                return f"Network path reaches VPC {target_label}"
            if rel == 'REFERENCES_SECRET':
                return f"{source_label} can read secret {target_label}"
            if rel == 'serves_from_bucket':
                return f"CloudFront serves from {target_label}"
            # Fallback
            return f"Reaches {target_label}"

        # Group nodes by BFS depth, skip INTERNET (depth 0)
        depth_groups: dict = {}
        for node_id, depth in bfs_layers.items():
            if depth == 0:
                continue
            depth_groups.setdefault(depth, []).append(node_id)

        # Pick the most interesting node at each depth (prefer data stores > compute > network)
        TYPE_PRIORITY = {
            'rds_instance': 0, 's3_bucket': 1, 'secretsmanager_secret': 2,
            'lambda_function': 3, 'ec2_instance': 4, 'elasticache_cluster': 5,
            'iam_role': 6, 'load_balancer': 7, 'api_gateway': 8,
            'security_group': 9, 'vpc_subnet': 10,
        }

        stages = []
        for depth in sorted(depth_groups.keys()):
            node_ids = depth_groups[depth]
            # Sort by priority (data stores first)
            scored = []
            for nid in node_ids:
                node = graph_obj.get_node(nid)
                if node:
                    scored.append((TYPE_PRIORITY.get(node['type'], 99), nid, node))
            scored.sort(key=lambda x: x[0])

            if not scored:
                continue

            # Pick the top node for the narrative caption
            _, best_id, best_node = scored[0]
            edge = parent_edge.get(best_id)

            if edge:
                caption = _caption_for_edge(edge, best_node)
            else:
                caption = f"Reaches {best_node.get('label', best_id)}"

            # Include up to 3 node_ids for graph highlighting
            highlight_ids = [s[1] for s in scored[:3]]

            stages.append({
                "order": len(stages) + 1,
                "caption": caption,
                "node_ids": highlight_ids,
                "color": "red" if depth <= 2 else "amber",
            })

        return stages[:8]  # cap at 8 stages

    attack_stages = _build_attack_stages(slice_dict, graph)

    # ── DETERMINISTIC: Compute blast radius from BFS ──────────────
    def _compute_blast_radius(slice_data: dict, graph_obj: Graph) -> dict:
        """Count reachable resources by type — no LLM needed."""
        bfs_layers = slice_data.get('layers', {})
        by_type = {}
        for node_id in bfs_layers:
            if node_id == 'INTERNET':
                continue
            node = graph_obj.get_node(node_id)
            if node:
                ntype = node['type']
                by_type.setdefault(ntype, []).append(node_id)

        # Friendly type names
        type_labels = {
            'ec2_instance': 'EC2',
            's3_bucket': 'S3',
            'rds_instance': 'RDS',
            'lambda_function': 'Lambda',
            'iam_role': 'IAM',
            'security_group': 'SG',
            'elasticache_cluster': 'Cache',
            'api_gateway': 'API GW',
            'vpc_subnet': 'Subnet',
            'load_balancer': 'LB',
            'secretsmanager_secret': 'Secret',
        }

        by_type_summary = {}
        for ntype, ids in by_type.items():
            label = type_labels.get(ntype, ntype)
            by_type_summary[label] = len(ids)

        total = sum(by_type_summary.values())
        return {"total": total, "by_type": by_type_summary}

    blast_radius = _compute_blast_radius(slice_dict, graph)

    # ── SMART DETERMINISTIC NARRATIVE (fallback that's actually good) ─
    def _build_deterministic_narrative(stages: list, blast: dict, query: str, graph_obj: Graph) -> dict:
        """Build a meaningful narrative from graph data alone — no LLM needed."""
        total = blast.get('total', 0)
        by_type = blast.get('by_type', {})

        # Determine severity from blast radius + what's reachable
        has_data_stores = any(t in by_type for t in ('S3', 'RDS', 'Secret', 'Cache'))
        has_iam = 'IAM' in by_type
        severity = "critical" if (total > 5 and has_data_stores) else "critical" if total > 10 else "moderate" if total > 3 else "low"

        # Build verdict from the most dangerous thing reachable
        data_targets = []
        if 'RDS' in by_type: data_targets.append(f"{by_type['RDS']} database{'s' if by_type['RDS'] > 1 else ''}")
        if 'S3' in by_type: data_targets.append(f"{by_type['S3']} S3 bucket{'s' if by_type['S3'] > 1 else ''}")
        if 'Secret' in by_type: data_targets.append(f"{by_type['Secret']} secret{'s' if by_type['Secret'] > 1 else ''}")

        compute_targets = []
        if 'EC2' in by_type: compute_targets.append(f"{by_type['EC2']} EC2 instance{'s' if by_type['EC2'] > 1 else ''}")
        if 'Lambda' in by_type: compute_targets.append(f"{by_type['Lambda']} Lambda function{'s' if by_type['Lambda'] > 1 else ''}")

        if data_targets:
            verdict = f"Full data exfiltration path exists. {', '.join(data_targets)} reachable from the internet in {len(stages)} hops."
        elif compute_targets:
            verdict = f"{', '.join(compute_targets)} directly exposed to the internet via open security groups."
        else:
            verdict = f"{total} resources reachable from the internet through permissive network configuration."

        # Build summary from attack stages
        if stages:
            first_stage = stages[0]['caption'] if stages else ""
            last_stage = stages[-1]['caption'] if len(stages) > 1 else ""
            hop_count = len(stages)

            if has_data_stores and has_iam:
                summary = (
                    f"An attacker can reach your data stores in {hop_count} hops. "
                    f"The chain starts with: {first_stage.lower()}. "
                    f"IAM role assumption enables lateral movement to {', '.join(data_targets)}."
                )
            elif has_data_stores:
                summary = (
                    f"Internet-facing resources provide a direct path to sensitive data. "
                    f"{', '.join(data_targets)} {'are' if len(data_targets) > 1 else 'is'} reachable through "
                    f"{hop_count} network hops via open security groups."
                )
            else:
                summary = (
                    f"{total} resources are reachable from the internet through permissive security group rules. "
                    f"The attack surface includes {', '.join(compute_targets) if compute_targets else f'{total} resources'} "
                    f"across {len(by_type)} resource types."
                )
        else:
            summary = f"Your infrastructure has {total} internet-reachable resources across {len(by_type)} types."

        # Follow-up based on what's exposed
        if has_data_stores:
            follow_up = "What specific data can be exfiltrated from the exposed storage?"
        elif has_iam:
            follow_up = "Which IAM roles have overly permissive policies?"
        elif 'SG' in by_type:
            follow_up = "Which security groups can be tightened without breaking connectivity?"
        else:
            follow_up = "What data is exposed from the internet?"

        return {"verdict": verdict, "severity": severity, "summary": summary, "follow_up": follow_up}

    # ── HAIKU WITH RETRY + SMART FALLBACK ─────────────────────────
    async def event_stream():
        import anthropic as anthropic_lib

        haiku_data = None
        # Raw mode: skip Haiku, use deterministic narrative.
        # MCP host is already an LLM, no need for second one.
        api_key = None if _is_raw_mode(http_request, raw) else os.getenv('ANTHROPIC_API_KEY')

        if api_key:
            # Trim graph text for faster response (keep first 2000 chars)
            trimmed_graph = graph_text[:2000] if len(graph_text) > 2000 else graph_text

            haiku_prompt = f"""You are analyzing AWS infrastructure security.

INFRASTRUCTURE (real, IAM-scanned):
{trimmed_graph}

Query: {request.query}
Blast radius: {blast_radius['total']} resources reachable ({', '.join(f'{v} {k}' for k, v in blast_radius['by_type'].items())})
Attack chain: {' → '.join(s['caption'][:60] for s in attack_stages[:4])}

Respond with ONLY JSON (no markdown):
{{"verdict": "one direct sentence answering the query", "severity": "low|moderate|critical", "summary": "2-3 sentences on situation and impact", "follow_up": "next question to ask"}}"""

            anthropic_client = anthropic_lib.Anthropic(api_key=api_key, timeout=15)

            for attempt in range(2):  # retry once
                try:
                    haiku_msg = anthropic_client.messages.create(
                        model="claude-haiku-4-5-20251001",
                        max_tokens=300,
                        messages=[{"role": "user", "content": haiku_prompt}]
                    )
                    haiku_raw = haiku_msg.content[0].text.strip().replace('```json', '').replace('```', '').strip()
                    haiku_data = json.loads(haiku_raw)
                    break  # success
                except Exception as e:
                    logger.warning(f"simulate: Haiku attempt {attempt + 1} failed: {e}")
                    if attempt == 0:
                        # Retry with even shorter prompt
                        haiku_prompt = f"""AWS security query: "{request.query}"
Blast radius: {blast_radius['total']} resources. Types: {blast_radius['by_type']}
Respond JSON only: {{"verdict": "1 sentence", "severity": "low|moderate|critical", "summary": "2 sentences", "follow_up": "next question"}}"""
                        anthropic_client = anthropic_lib.Anthropic(api_key=api_key, timeout=10)

        # Use smart deterministic fallback if Haiku failed
        if not haiku_data:
            haiku_data = _build_deterministic_narrative(attack_stages, blast_radius, request.query, graph)

        # ── Send preview immediately ──────────────────────────────
        preview_data = {
            "verdict": haiku_data.get("verdict", ""),
            "severity": haiku_data.get("severity", "low"),
            "summary": haiku_data.get("summary", ""),
        }
        yield f"event: preview\ndata: {json.dumps(preview_data)}\n\n"

        # ── Send complete with deterministic attack chain + blast radius ──
        complete_data = {
            "verdict": haiku_data.get("verdict", ""),
            "severity": haiku_data.get("severity", "low"),
            "summary": haiku_data.get("summary", ""),
            "stages": attack_stages,
            "blast_radius": blast_radius,
            "follow_up": haiku_data.get("follow_up", ""),
            "category": category,
            "query": request.query,
        }
        yield f"event: complete\ndata: {json.dumps(complete_data)}\n\n"

        # ── LOG SIMULATION FOR DAILY LIMIT TRACKING ───────────────
        if aws_account_id:
            try:
                save_simulation_log(aws_account_id, request.analysis_id, request.query)
            except Exception as sim_log_err:
                logger.warning(f"simulate: failed to save simulation log: {sim_log_err}")

    return StreamingResponse(event_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get('/simulate/remaining')
def simulate_remaining(analysis_id: str):
    """Returns how many simulations remain today for the account that owns this analysis."""
    SIMULATION_DAILY_LIMIT = 10
    from app.database import SessionLocal, AnalysisLog

    aws_account_id = None
    try:
        session = SessionLocal()
        try:
            logs = session.query(AnalysisLog).order_by(AnalysisLog.timestamp.desc()).limit(100).all()
            for log in logs:
                try:
                    data = json.loads(log.findings_json)
                    if data.get('analysis_id') == analysis_id:
                        aws_account_id = log.aws_account_id or None
                        break
                except Exception:
                    continue
        finally:
            session.close()
    except Exception:
        pass

    if not aws_account_id:
        return {'remaining': SIMULATION_DAILY_LIMIT, 'limit': SIMULATION_DAILY_LIMIT, 'used': 0}

    # Whitelisted accounts get unlimited simulations
    WHITELISTED_ACCOUNTS = set(filter(None, os.getenv('WHITELISTED_ACCOUNTS', '').split(',')))
    if aws_account_id in WHITELISTED_ACCOUNTS:
        return {'remaining': SIMULATION_DAILY_LIMIT, 'limit': SIMULATION_DAILY_LIMIT, 'used': 0}

    used = get_simulation_count_today(aws_account_id)
    remaining = max(0, SIMULATION_DAILY_LIMIT - used)
    return {'remaining': remaining, 'limit': SIMULATION_DAILY_LIMIT, 'used': used}


@app.get('/usage/remaining')
def usage_remaining(account_id: str = Query(...)):
    """Returns daily usage counts and limits for all rate-limited features."""
    if not account_id:
        raise HTTPException(status_code=400, detail="account_id required")

    scans_used = get_scan_count_today(account_id)
    sim_used = get_simulation_count_today(account_id)
    insights_used = get_llm_usage_count_today(account_id, "insight")
    terraform_used = get_llm_usage_count_today(account_id, "terraform")

    return {
        "scans": {"used": scans_used, "limit": DAILY_SCAN_LIMIT},
        "simulations": {"used": sim_used, "limit": 10},
        "insights": {"used": insights_used, "limit": 5},
        "terraform": {"used": terraform_used, "limit": 10}
    }


@app.post('/remediation/generate-insight', response_model=RemediationInsightResponse)
def generate_remediation_insight(request: RemediationInsightRequest, http_request: Request, raw: bool = False):
    """
    Generate AI-powered 'What this fixes' and 'Why it matters' text for a single finding.
    Rate limited to 5 requests/minute per IP.
    Never errors beyond 429 — falls back to static text derived from the finding if Gemini fails.
    """
    # Raw mode: MCP caller renders its own text, return empty
    if _is_raw_mode(http_request, raw):
        return RemediationInsightResponse(what_this_fixes='', why_it_matters='')

    # Rate limit: 5 requests/minute per IP
    client_ip = http_request.client.host if http_request.client else 'unknown'
    _check_insight_rate_limit(client_ip)

    # ── ACCOUNT-BASED DAILY LIMIT: 5/day per account ─────────────
    INSIGHT_DAILY_LIMIT = 5
    WHITELISTED_ACCOUNTS = set(filter(None, os.getenv('WHITELISTED_ACCOUNTS', '').split(',')))
    account_id = request.account_id
    if account_id and account_id not in WHITELISTED_ACCOUNTS:
        insight_used = get_llm_usage_count_today(account_id, "insight")
        if insight_used >= INSIGHT_DAILY_LIMIT:
            raise HTTPException(
                status_code=429,
                detail=f'Daily insight limit reached. Your account has used {insight_used}/{INSIGHT_DAILY_LIMIT} insights today. Resets at midnight UTC.'
            )

    from google import genai
    import json

    attack_path_str = ' → '.join(request.attack_path) if request.attack_path else 'N/A'
    resource_str = request.resource_id or 'N/A'

    prompt = f"""You are an AWS security advisor. A developer is looking at a specific security finding in their AWS account and needs two short, plain-English explanations.

Finding details:
- Service: {request.aws_service}
- Severity: {request.severity}
- Issue: {request.issue}
- Resource: {resource_str}
- Region: {request.region or 'N/A'}
- Attack path: {attack_path_str}
- Current recommendation: {request.recommendation}

Write two short paragraphs (2-3 sentences each) in plain English. No jargon. Write like you are explaining to a smart developer who is not an AWS security expert.

Respond with valid JSON only — no markdown, no code fences:
{{
  "what_this_fixes": "2-3 sentences explaining exactly what applying the fix will change in the AWS configuration and what threat it removes.",
  "why_it_matters": "2-3 sentences describing the real-world risk if this is NOT fixed. Describe a concrete attacker scenario specific to this finding and resource."
}}"""

    try:
        api_key = os.getenv('GEMINI_API_KEY')
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt
        )
        text = response.text.strip().replace('```json', '').replace('```', '').strip()
        result = json.loads(text)

        # Track usage after successful generation
        if account_id:
            save_llm_usage(account_id, "insight")

        return RemediationInsightResponse(
            what_this_fixes=result.get('what_this_fixes', request.recommendation),
            why_it_matters=result.get('why_it_matters', f'This {request.severity.lower()} {request.aws_service} issue should be resolved promptly to reduce your attack surface.')
        )
    except Exception as e:
        # Graceful fallback — never surface an error to the frontend
        logger.warning(f"Gemini insight generation failed for {request.resource_id}: {type(e).__name__}: {e}")
        return RemediationInsightResponse(
            what_this_fixes=request.recommendation,
            why_it_matters=f'This {request.severity.lower()} security issue in {request.aws_service} could expose your infrastructure to unauthorized access or data loss if left unresolved.'
        )


# Category-specific Terraform fix instructions for the LLM
_TERRAFORM_FIX_GUIDANCE = {
    'EMFIRGE-EC2-002': 'Remove the ingress rule allowing SSH (port 22) from 0.0.0.0/0. Replace with a restricted CIDR like the VPC range or a specific IP/32.',
    'EMFIRGE-EC2-003': 'Remove the ingress rule allowing RDP (port 3389) from 0.0.0.0/0. Replace with a restricted CIDR.',
    'EMFIRGE-EC2-010': 'Remove the wide-open ingress rule (all ports or wide range). Replace with specific port rules for only required services.',
    'EMFIRGE-EC2-011': 'Remove the ingress rule exposing this admin port to 0.0.0.0/0. Restrict to a specific trusted IP/32 or VPC CIDR.',
    'EMFIRGE-EC2-012': 'Remove the ingress rule exposing this database port to 0.0.0.0/0. Databases must only be accessible from within the VPC.',
    'EMFIRGE-EC2-013': 'Remove the ingress rule exposing this internal service port to 0.0.0.0/0. Restrict to VPC CIDR only.',
    'EMFIRGE-EC2-014': 'Remove the ingress rule exposing this unusual port to 0.0.0.0/0. If the port is needed, restrict to a specific IP/32 or VPC CIDR.',
    'EMFIRGE-S3-001': 'Add an aws_s3_bucket_public_access_block resource that blocks all public access (block_public_acls=true, block_public_policy=true, ignore_public_acls=true, restrict_public_buckets=true).',
    'EMFIRGE-S3-002': 'Add server-side encryption configuration using aws_s3_bucket_server_side_encryption_configuration with AES256 or aws:kms.',
    'EMFIRGE-S3-003': 'Enable versioning using aws_s3_bucket_versioning with status="Enabled".',
    'EMFIRGE-RDS-002': 'Set publicly_accessible=false on the aws_db_instance resource.',
    'EMFIRGE-RDS-003': 'Set storage_encrypted=true on the aws_db_instance resource.',
    'EMFIRGE-RDS-004': 'Set deletion_protection=true on the aws_db_instance resource.',
    'EMFIRGE-IAM-001': 'Remove root access keys. Use aws_iam_access_key resource deletion or document that root keys must be manually deleted in console.',
    'EMFIRGE-VPC-001': 'Add aws_flow_log resource attached to the VPC with a CloudWatch log group destination.',
    'EMFIRGE-KMS-001': 'Set enable_key_rotation=true on the aws_kms_key resource.',
}


def _get_fix_guidance(rule_id: str) -> str:
    """Get category-specific fix guidance for the LLM prompt."""
    if not rule_id:
        return ''
    # Exact match first
    if rule_id in _TERRAFORM_FIX_GUIDANCE:
        return f"\n\nSPECIFIC FIX REQUIRED:\n{_TERRAFORM_FIX_GUIDANCE[rule_id]}"
    # Prefix match (e.g., EMFIRGE-EC2 covers all EC2 open port variants)
    prefix = '-'.join(rule_id.split('-')[:2])
    for key, guidance in _TERRAFORM_FIX_GUIDANCE.items():
        if key.startswith(prefix):
            return f"\n\nSPECIFIC FIX REQUIRED:\n{guidance}"
    return ''


def _validate_hcl_output(hcl: str, request: TerraformGenerateRequest) -> bool:
    """Check if generated HCL contradicts the fix intent (e.g., still has 0.0.0.0/0 for an open-access finding)."""
    issue_lower = (request.issue or '').lower()
    # If the finding is about something being open to the internet,
    # the fix should NOT contain 0.0.0.0/0 or ::/0 as a CIDR source
    is_open_access_finding = any(phrase in issue_lower for phrase in [
        'open to the internet', 'open to 0.0.0.0', 'publicly accessible',
        'public access', 'exposed to the public'
    ])
    if is_open_access_finding:
        # Check if HCL still has wide-open CIDR (but allow it in comments)
        for line in hcl.split('\n'):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            if '0.0.0.0/0' in stripped or '::/0' in stripped:
                return False
    return True


@app.post('/remediation/generate-terraform', response_model=TerraformGenerateResponse)
def generate_terraform(request: TerraformGenerateRequest, http_request: Request, raw: bool = False):
    # Raw mode: MCP host generates HCL itself, skip Claude
    if _is_raw_mode(http_request, raw):
        return TerraformGenerateResponse(hcl='', filename=f"{(request.rule_id or 'fix').lower()}.tf", valid=None, errors=None)

    client_ip = http_request.client.host if http_request.client else 'unknown'
    _check_terraform_rate_limit(client_ip)

    # ── ACCOUNT-BASED DAILY LIMIT: 5/day per account ─────────────
    TERRAFORM_DAILY_LIMIT = 5
    WHITELISTED_ACCOUNTS = set(filter(None, os.getenv('WHITELISTED_ACCOUNTS', '').split(',')))
    account_id = request.account_id
    if account_id and account_id not in WHITELISTED_ACCOUNTS:
        terraform_used = get_llm_usage_count_today(account_id, "terraform")
        if terraform_used >= TERRAFORM_DAILY_LIMIT:
            raise HTTPException(
                status_code=429,
                detail=f'Daily Terraform limit reached. Your account has used {terraform_used}/{TERRAFORM_DAILY_LIMIT} fixes today. Resets at midnight UTC.'
            )

    import anthropic
    import shutil

    try:
        client = anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))
        fix_guidance = _get_fix_guidance(request.rule_id)

        prompt = f"""You are fixing a specific AWS security misconfiguration in Terraform.

FINDING:
- Rule: {request.rule_id}
- Issue: {request.issue}
- Resource ID: {request.resource_id} ({request.resource_type} in {request.region})
- Severity: {request.severity}
- Why dangerous: {request.recommendation}
- Attack path: {' -> '.join(request.attack_path or [])}
{fix_guidance}

Generate the SMALLEST possible Terraform HCL that FIXES this issue.

CRITICAL RULES:
1. Output ONLY valid Terraform HCL. No explanation, no markdown fences.
2. Add a comment at the top: # EMFIRGE FIX: {request.issue}
3. The fix must REMOVE or RESTRICT the dangerous configuration — never recreate it.
4. For open port/access findings: NEVER include cidr_ipv4="0.0.0.0/0" or cidr_ipv6="::/0" in your fix. Use a restricted CIDR like "10.0.0.0/8" or reference a specific IP.
5. For security group fixes: use aws_vpc_security_group_ingress_rule to define the RESTRICTED replacement rule (not the open one).
6. Never use placeholder values like CHANGE_ME or YOUR_VALUE. Use realistic restricted values.
7. Target resource type: {request.resource_type}

EXAMPLE — Fixing "port 22 open to 0.0.0.0/0" on sg-abc123:
CORRECT:
# EMFIRGE FIX: SSH port 22 open to 0.0.0.0/0
resource "aws_vpc_security_group_ingress_rule" "restrict_ssh" {{
  security_group_id = "sg-abc123"
  description       = "Restrict SSH to VPC CIDR only"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  cidr_ipv4         = "10.0.0.0/8"
}}

WRONG (this recreates the vulnerability):
resource "aws_vpc_security_group_ingress_rule" "fix_ssh" {{
  security_group_id = "sg-abc123"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}}"""

        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}]
        )
        hcl = message.content[0].text.strip()

        # Post-generation validation: check if output contradicts the fix intent
        if not _validate_hcl_output(hcl, request):
            logger.warning(f"Terraform fix for {request.rule_id} still contains open CIDR — retrying with correction")
            correction_msg = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=1024,
                messages=[
                    {"role": "user", "content": prompt},
                    {"role": "assistant", "content": hcl},
                    {"role": "user", "content": "WRONG. Your output still contains 0.0.0.0/0 or ::/0 which is the vulnerability we are trying to fix. Regenerate using a restricted CIDR like 10.0.0.0/8 or a specific private IP range. Output ONLY the corrected HCL."}
                ]
            )
            hcl = correction_msg.content[0].text.strip()

        filename = f"{(request.rule_id or 'fix').lower()}.tf"
        valid, errors = None, None
        if not shutil.which('terraform'):
            valid = None
            errors = 'terraform CLI not available — skipping validation'
        else:
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    tf_path = os.path.join(tmpdir, 'fix.tf')
                    with open(tf_path, 'w') as f:
                        f.write(hcl)
                    result = subprocess.run(
                        ['terraform', 'validate'],
                        cwd=tmpdir, capture_output=True, timeout=30, text=True
                    )
                    if result.returncode != 0:
                        valid, errors = False, result.stderr
                    else:
                        valid = True
            except Exception:
                pass

        # Track usage after successful generation
        if account_id:
            save_llm_usage(account_id, "terraform")

        return TerraformGenerateResponse(hcl=hcl, filename=filename, valid=valid, errors=errors)
    except Exception as e:
        logger.error(f"Terraform generation failed for {request.rule_id}: {type(e).__name__}: {e}")
        return TerraformGenerateResponse(hcl='', filename='fix.tf', valid=False, errors=str(e))


@app.post('/remediation/verify-fix', response_model=VerifyFixResponse)
def verify_fix(request: VerifyFixRequest, http_request: Request):
    """
    Simulate applying a fix for a specific finding and return the impact.

    1. Look up FIX_MUTATIONS[rule_id]
    2. If not found → return {can_simulate: false}
    3. Load infrastructure from DB
    4. Deep-copy, apply mutation
    5. Rebuild graph, run rules, diff findings, calculate score delta
    6. Return VerifyFixResponse

    Pure computation — no LLM calls, no side effects. Should be <1s.
    """
    import copy
    from app.fix_mutations import FIX_MUTATIONS

    # ── CHECK IF WE CAN SIMULATE THIS RULE ────────────────────────
    if request.rule_id not in FIX_MUTATIONS:
        return VerifyFixResponse(can_simulate=False)

    # ── LOAD INFRASTRUCTURE FROM DB ───────────────────────────────
    from app.database import SessionLocal, AnalysisLog

    infrastructure = None
    original_findings_data = None
    try:
        session = SessionLocal()
        try:
            logs = session.query(AnalysisLog).order_by(AnalysisLog.timestamp.desc()).limit(100).all()
            for log in logs:
                try:
                    data = json.loads(log.findings_json)
                    if data.get('analysis_id') == request.analysis_id:
                        infra_dict = data.get('infrastructure', {})
                        infrastructure = AWSInfrastructure(**infra_dict)
                        original_findings_data = data
                        break
                except Exception:
                    continue
        finally:
            session.close()
    except Exception as e:
        logger.error(f"verify_fix: DB load failed: {e}")

    if not infrastructure:
        raise HTTPException(status_code=404, detail='Scan data not found for this analysis ID.')

    # ── DEEP-COPY AND APPLY MUTATION ──────────────────────────────
    mutated_infra_dict = copy.deepcopy(infrastructure.model_dump())
    mutation_fn = FIX_MUTATIONS[request.rule_id]
    applied = mutation_fn(mutated_infra_dict, request.resource_id)

    if not applied:
        return VerifyFixResponse(can_simulate=False)

    # ── REBUILD GRAPH + RUN CHECKS ────────────────────────────────
    mutated_infra = AWSInfrastructure(**mutated_infra_dict)
    mutated_graph = build_graph(mutated_infra)
    mutated_findings = run_all_checks(mutated_infra, mutated_graph)
    mutated_combos = find_toxic_combos(mutated_findings, mutated_graph, mutated_infra)

    # ── DIFF FINDINGS ─────────────────────────────────────────────
    def finding_key(f):
        rid = f.get('rule_id', '') or (f.rule_id if hasattr(f, 'rule_id') else '')
        res = f.get('resource_id', '') or (f.resource_id if hasattr(f, 'resource_id') else '')
        return (rid, res)

    # Original finding keys
    original_keys = set()
    original_findings_list = []
    for category in ['critical_risks', 'moderate_risks', 'low_risks', 'best_practices', 'cost_findings']:
        for f in original_findings_data.get(category, []):
            original_keys.add(finding_key(f))
            original_findings_list.append(f)

    # Mutated finding keys
    mutated_keys = set()
    mutated_findings_list = []
    for category in ['critical_risks', 'moderate_risks', 'low_risks', 'best_practices', 'cost_findings']:
        for f in mutated_findings.get(category, []):
            f_dict = f.model_dump() if hasattr(f, 'model_dump') else f
            mutated_keys.add(finding_key(f_dict))
            mutated_findings_list.append(f_dict)

    # Findings removed (were in original, not in mutated)
    removed_keys = original_keys - mutated_keys
    findings_removed = [f for f in original_findings_list if finding_key(f) in removed_keys]

    # Findings added (in mutated, not in original) — shouldn't happen for a fix, but track it
    added_keys = mutated_keys - original_keys
    findings_added = [f for f in mutated_findings_list if finding_key(f) in added_keys]

    # ── DIFF TOXIC COMBOS ─────────────────────────────────────────
    original_combo_ids = {c.get('combo_id', '') for c in original_findings_data.get('toxic_combinations', [])}
    mutated_combo_ids = {(c.get('combo_id') if isinstance(c, dict) else c.combo_id) for c in mutated_combos}

    combos_resolved = list(original_combo_ids - mutated_combo_ids)
    combos_created = list(mutated_combo_ids - original_combo_ids)

    # ── CALCULATE SCORE DELTA ─────────────────────────────────────
    original_score = original_findings_data.get('overall_risk_score', 0)
    total_resources = original_findings_data.get('total_resources_scanned', 1)
    mutated_scores = calculate_score(mutated_findings, total_resources, mutated_infra)
    mutated_score = mutated_scores.get('overall_risk_score', 0)
    score_delta = mutated_score - original_score

    # safe_to_apply = no new RISK findings introduced (ignore best_practices which are positive signals)
    risk_findings_added = [f for f in findings_added if f.get('severity', '').lower() in ('critical', 'moderate', 'high')]
    safe = len(risk_findings_added) == 0 and score_delta >= 0

    return VerifyFixResponse(
        can_simulate=True,
        findings_removed=findings_removed,
        findings_added=findings_added,
        toxic_combos_resolved=combos_resolved,
        toxic_combos_created=combos_created,
        score_before=original_score,
        score_after=mutated_score,
        score_delta=score_delta,
        safe_to_apply=safe,
    )


# ── UNIFIED FIX ENDPOINT ─────────────────────────────────────────────


def _apply_rule_based_mutation(infra_dict: dict, rule_id: str, resource_id: str) -> bool:
    """
    Apply a mutation based on rule_id knowledge. Covers all 58 rules.
    Returns True if mutation was applied, False if not applicable.
    """
    rid = rule_id.upper() if rule_id else ""

    # ── EC2 / Security Group rules ────────────────────────────────
    if rid in ('EMFIRGE-EC2-002', 'EMFIRGE-EC2-003', 'EMFIRGE-EC2-004', 'EMFIRGE-EC2-005',
               'EMFIRGE-EC2-006', 'EMFIRGE-EC2-007', 'EMFIRGE-EC2-008', 'EMFIRGE-EC2-010',
               'EMFIRGE-EC2-011', 'EMFIRGE-EC2-012', 'EMFIRGE-EC2-013', 'EMFIRGE-EC2-014',
               'EMFIRGE-EC2-015', 'EMFIRGE-EC2-017', 'EMFIRGE-EC2-018'):
        # All open port / SG rules: remove 0.0.0.0/0 rules from the SG
        for sg in infra_dict.get('ec2', {}).get('security_groups', []):
            if sg['id'] == resource_id:
                sg['rules'] = [r for r in sg.get('rules', [])
                               if '0.0.0.0/0' not in r.get('ip_ranges', []) and '::/0' not in r.get('ip_ranges', [])]
                infra_dict['ec2']['ssh_open_to_internet'] = False
                infra_dict['ec2']['rdp_open_to_internet'] = False
                return True
        for inst in infra_dict.get('ec2', {}).get('instances', []):
            if inst['id'] == resource_id:
                for sg_id in inst.get('sg_ids', []):
                    for sg in infra_dict.get('ec2', {}).get('security_groups', []):
                        if sg['id'] == sg_id:
                            sg['rules'] = [r for r in sg.get('rules', [])
                                           if '0.0.0.0/0' not in r.get('ip_ranges', [])]
                            return True
        return False

    if rid in ('EMFIRGE-EC2-009', 'EMFIRGE-EC2-016'):
        for inst in infra_dict.get('ec2', {}).get('instances', []):
            if inst['id'] == resource_id:
                inst['imdsv2_required'] = True
                return True
        return False

    if rid == 'EMFIRGE-EC2-001':
        infra_dict['ec2']['has_auto_scaling'] = True
        return True

    # ── S3 rules ──────────────────────────────────────────────────
    if rid == 'EMFIRGE-S3-001':
        for bucket in infra_dict.get('s3', {}).get('buckets', []):
            if bucket['name'] == resource_id:
                bucket['is_public'] = False
                bucket['policy'] = None
                pub = infra_dict['s3'].get('public_buckets', [])
                if resource_id in pub:
                    pub.remove(resource_id)
                return True
        return False

    if rid == 'EMFIRGE-S3-002':
        unenc = infra_dict.get('s3', {}).get('unencrypted_buckets', [])
        if resource_id in unenc:
            unenc.remove(resource_id)
            return True
        return True

    if rid == 'EMFIRGE-S3-003':
        no_ver = infra_dict.get('s3', {}).get('buckets_without_versioning', [])
        if resource_id in no_ver:
            no_ver.remove(resource_id)
            return True
        return True

    if rid == 'EMFIRGE-S3-004':
        infra_dict['s3']['logging_enabled'] = True
        return True

    # ── RDS rules ─────────────────────────────────────────────────
    if rid == 'EMFIRGE-RDS-001':
        infra_dict['rds']['backup_retention_days'] = 7
        return True

    if rid == 'EMFIRGE-RDS-002':
        for rds in infra_dict.get('rds', {}).get('rds_instances', []):
            if rds['id'] == resource_id:
                rds['publicly_accessible'] = False
                pub = infra_dict['rds'].get('publicly_accessible', [])
                if resource_id in pub:
                    pub.remove(resource_id)
                return True
        return False

    if rid == 'EMFIRGE-RDS-003':
        for rds in infra_dict.get('rds', {}).get('rds_instances', []):
            if rds['id'] == resource_id:
                rds['encrypted'] = True
                unenc = infra_dict['rds'].get('unencrypted_instances', [])
                if resource_id in unenc:
                    unenc.remove(resource_id)
                return True
        return False

    if rid == 'EMFIRGE-RDS-004':
        no_dp = infra_dict.get('rds', {}).get('instances_without_deletion_protection', [])
        if resource_id in no_dp:
            no_dp.remove(resource_id)
            return True
        return True

    if rid == 'EMFIRGE-RDS-005':
        infra_dict['rds']['log_exports_enabled'] = True
        return True

    if rid == 'EMFIRGE-RDS-006':
        infra_dict['rds']['multi_az_enabled'] = True
        return True

    if rid == 'EMFIRGE-RDS-007':
        infra_dict['rds']['backup_retention_days'] = 14
        return True

    # ── IAM rules ─────────────────────────────────────────────────
    if rid in ('EMFIRGE-IAM-001', 'EMFIRGE-IAM-002', 'EMFIRGE-IAM-003',
               'EMFIRGE-IAM-004', 'EMFIRGE-IAM-005', 'EMFIRGE-IAM-006'):
        admin_users = infra_dict.get('iam', {}).get('users_with_admin_policy', [])
        if resource_id in admin_users:
            admin_users.remove(resource_id)
        infra_dict['iam']['all_users_have_mfa'] = True
        infra_dict['iam']['root_has_access_keys'] = False
        old_keys = infra_dict.get('iam', {}).get('users_with_old_keys', [])
        if resource_id in old_keys:
            old_keys.remove(resource_id)
        return True

    # ── Lambda rules ──────────────────────────────────────────────
    if rid == 'EMFIRGE-LAMBDA-001':
        for func in infra_dict.get('lambda_data', {}).get('functions', []):
            if func['name'] == resource_id:
                func['vpc_id'] = 'vpc-fixed'
                func['subnet_ids'] = ['subnet-fixed']
                return True
        return False

    if rid == 'EMFIRGE-LAMBDA-002':
        for func in infra_dict.get('lambda_data', {}).get('functions', []):
            if func['name'] == resource_id:
                func['runtime'] = 'python3.12'
                return True
        return False

    if rid in ('EMFIRGE-LAMBDA-003', 'EMFIRGE-LAMBDA-004'):
        for func in infra_dict.get('lambda_data', {}).get('functions', []):
            if func['name'] == resource_id:
                func['role_arn'] = 'arn:aws:iam::000:role/restricted-role'
                return True
        return False

    # ── CloudTrail rules ──────────────────────────────────────────
    if rid in ('EMFIRGE-CT-001', 'EMFIRGE-CT-002', 'EMFIRGE-CT-003'):
        infra_dict['cloudtrail']['is_enabled'] = True
        infra_dict['cloudtrail']['is_multi_region'] = True
        infra_dict['cloudtrail']['has_log_validation'] = True
        return True

    # ── CloudWatch ────────────────────────────────────────────────
    if rid == 'EMFIRGE-CW-001':
        infra_dict['cloudwatch']['has_alarms'] = True
        infra_dict['cloudwatch']['has_billing_alarm'] = True
        return True

    # ── GuardDuty ─────────────────────────────────────────────────
    if rid in ('EMFIRGE-GD-001', 'EMFIRGE-GUARD-001'):
        infra_dict['guardduty']['is_enabled'] = True
        infra_dict['guardduty']['detector_id'] = 'simulated-detector'
        return True

    # ── WAF ───────────────────────────────────────────────────────
    if rid == 'EMFIRGE-WAF-001':
        albs_without = infra_dict.get('waf', {}).get('albs_without_waf', [])
        if resource_id in albs_without:
            albs_without.remove(resource_id)
        return True

    # ── VPC rules ─────────────────────────────────────────────────
    if rid in ('EMFIRGE-VPC-001', 'EMFIRGE-VPC-002', 'EMFIRGE-VPC-003'):
        infra_dict['vpc']['has_flow_logs'] = True
        return True

    # ── Secrets Manager ───────────────────────────────────────────
    if rid == 'EMFIRGE-SM-001':
        infra_dict['secrets_manager']['all_rotated'] = True
        return True

    # ── KMS ───────────────────────────────────────────────────────
    if rid in ('EMFIRGE-KMS-001', 'EMFIRGE-KMS-002'):
        infra_dict['kms']['all_keys_rotating'] = True
        infra_dict['kms']['keys_pending_deletion'] = []
        return True

    # ── AWS Config ────────────────────────────────────────────────
    if rid in ('EMFIRGE-CFG-001', 'EMFIRGE-CFG-002'):
        infra_dict['config']['is_enabled'] = True
        infra_dict['config']['non_compliant_rules'] = []
        return True

    # ── SNS ───────────────────────────────────────────────────────
    if rid in ('EMFIRGE-SNS-001', 'EMFIRGE-SNS-002'):
        infra_dict['sns']['all_encrypted'] = True
        infra_dict['sns']['public_topics'] = []
        return True

    # ── ECS ───────────────────────────────────────────────────────
    if rid in ('EMFIRGE-ECS-001', 'EMFIRGE-ECS-002'):
        infra_dict['ecs']['privileged_tasks'] = []
        infra_dict['ecs']['no_resource_limits'] = False
        return True

    return False


@app.post('/remediation/fix')
def unified_fix(request: TerraformGenerateRequest, http_request: Request, raw: bool = False):
    """
    Unified fix endpoint: generates HCL + verifies it in one call.

    Flow:
    1. If rule_id has a deterministic mutation → verify instantly + generate HCL in parallel
    2. If not → generate HCL via Claude → parse HCL → simulate → verify
    3. Fallback: if HCL parsing fails → return HCL without verification

    Returns both the terraform fix AND the verification result.
    Rate limited: 5/min per IP + 10/day per account.
    """
    # ── RATE LIMIT: 5/min per IP ──────────────────────────────────
    client_ip = http_request.client.host if http_request.client else 'unknown'
    _check_terraform_rate_limit(client_ip)

    # ── DAILY LIMIT: 10/day per account ───────────────────────────
    FIX_DAILY_LIMIT = 10
    WHITELISTED_ACCOUNTS = set(filter(None, os.getenv('WHITELISTED_ACCOUNTS', '').split(',')))
    account_id = request.account_id
    if account_id and account_id not in WHITELISTED_ACCOUNTS:
        fix_used = get_llm_usage_count_today(account_id, "terraform")
        if fix_used >= FIX_DAILY_LIMIT:
            raise HTTPException(
                status_code=429,
                detail=f'Daily fix limit reached. Your account has used {fix_used}/{FIX_DAILY_LIMIT} remediation fixes today. Resets at midnight UTC.'
            )

    import copy
    import anthropic
    from app.fix_mutations import FIX_MUTATIONS
    from app.tf_parser import parse_hcl_to_component

    analysis_id = request.analysis_id
    # Try to get analysis_id from the request or from recent scans
    if not analysis_id:
        recent = get_recent_logs(limit=1)
        if recent:
            analysis_id = str(recent[0]['id'])

    # ── LOAD INFRASTRUCTURE ───────────────────────────────────────
    infrastructure = None
    original_findings_data = None

    if analysis_id:
        try:
            from app.database import SessionLocal, AnalysisLog
            session = SessionLocal()
            try:
                logs = session.query(AnalysisLog).order_by(AnalysisLog.timestamp.desc()).limit(100).all()
                for log in logs:
                    try:
                        data = json.loads(log.findings_json)
                        if data.get('analysis_id') == analysis_id:
                            infra_dict = data.get('infrastructure', {})
                            if infra_dict:
                                infrastructure = AWSInfrastructure(**infra_dict)
                                original_findings_data = data
                            break
                    except Exception:
                        continue
            finally:
                session.close()
        except Exception as e:
            logger.error(f"unified_fix: DB load failed: {e}")

    # ── GENERATE HCL (Claude) ─────────────────────────────────────
    # ── GENERATE HCL (Claude) ─────────────────────────────────────
    hcl = ""
    filename = f"{(request.rule_id or 'fix').lower()}.tf"
    # Raw mode: skip Claude, host LLM generates HCL itself.
    # Verification still runs below since it's deterministic.
    if not _is_raw_mode(http_request, raw):
      try:
        client = anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))
        fix_guidance = _get_fix_guidance(request.rule_id)

        prompt = f"""You are fixing a specific AWS security misconfiguration in Terraform.

FINDING:
- Rule: {request.rule_id}
- Issue: {request.issue}
- Resource ID: {request.resource_id} ({request.resource_type} in {request.region})
- Severity: {request.severity}
- Why dangerous: {request.recommendation}
- Attack path: {' -> '.join(request.attack_path or [])}
{fix_guidance}

Generate the SMALLEST possible Terraform HCL that FIXES this issue.

CRITICAL RULES:
1. Output ONLY valid Terraform HCL. No explanation, no markdown fences.
2. Add a comment at the top: # EMFIRGE FIX: {request.issue}
3. The fix must REMOVE or RESTRICT the dangerous configuration — never recreate it.
4. For open port/access findings: NEVER include cidr_ipv4="0.0.0.0/0" or cidr_ipv6="::/0" in your fix.
5. For security group fixes: use aws_vpc_security_group_ingress_rule to define the RESTRICTED replacement rule.
6. Never use placeholder values. Use realistic restricted values.
7. Target resource type: {request.resource_type}"""

        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}]
        )
        hcl = message.content[0].text.strip()

        # Post-generation validation
        if not _validate_hcl_output(hcl, request):
            correction_msg = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=1024,
                messages=[
                    {"role": "user", "content": prompt},
                    {"role": "assistant", "content": hcl},
                    {"role": "user", "content": "WRONG. Your output still contains 0.0.0.0/0 or ::/0. Regenerate using a restricted CIDR like 10.0.0.0/8. Output ONLY the corrected HCL."}
                ]
            )
            hcl = correction_msg.content[0].text.strip()

        # Track usage
        account_id = request.account_id
        if account_id:
            save_llm_usage(account_id, "terraform")

      except Exception as e:
        logger.error(f"unified_fix: HCL generation failed: {e}")
        hcl = f"# Generation failed: {str(e)[:50]}"

    # ── VERIFY THE FIX ────────────────────────────────────────────
    verification = {
        "can_simulate": False,
        "method": "unverified",
        "score_before": 0,
        "score_after": 0,
        "score_delta": 0,
        "findings_removed": [],
        "findings_added": [],
        "toxic_combos_resolved": [],
        "safe_to_apply": False,
    }

    if infrastructure and original_findings_data:
        rule_id = request.rule_id or ""
        resource_id = request.resource_id or ""

        # Build original finding keys
        original_finding_keys = set()
        for category in ['critical_risks', 'moderate_risks', 'low_risks', 'best_practices', 'cost_findings']:
            for f in original_findings_data.get(category, []):
                original_finding_keys.add((f.get('rule_id', ''), f.get('resource_id', '')))

        original_score = original_findings_data.get('overall_risk_score', 0)
        total_resources = original_findings_data.get('total_resources_scanned', 1)

        mutated_infra_dict = copy.deepcopy(infrastructure.model_dump())
        applied = False

        # PATH A: Deterministic mutation (fast, exact)
        if rule_id in FIX_MUTATIONS:
            mutation_fn = FIX_MUTATIONS[rule_id]
            applied = mutation_fn(mutated_infra_dict, resource_id)
            if applied:
                verification["method"] = "deterministic"

        # PATH B: Rule-based intelligent mutation (covers ALL rules)
        # Instead of parsing Claude's HCL, we know what each rule_id MEANS
        # and can apply the correct mutation directly based on the rule.
        if not applied and hcl and not hcl.startswith("# Generation failed"):
            try:
                applied = _apply_rule_based_mutation(mutated_infra_dict, rule_id, resource_id)
                if applied:
                    verification["method"] = "llm_simulated"
            except Exception as e:
                logger.warning(f"unified_fix: rule-based mutation failed: {e}")

            # Fallback: try parsing Claude's HCL if rule-based didn't work
            if not applied:
                try:
                    component = parse_hcl_to_component(hcl)
                    if component:
                        comp_type = component['component_type']
                        config = component.get('config', {})

                        if comp_type == 'security_group':
                            for sg in mutated_infra_dict.get('ec2', {}).get('security_groups', []):
                                if sg['id'] == resource_id:
                                    sg['rules'] = [r for r in sg.get('rules', []) if '0.0.0.0/0' not in r.get('ip_ranges', [])]
                                    applied = True
                                    break

                        elif comp_type == 'ec2_instance':
                            if config.get('imdsv2_required'):
                                for inst in mutated_infra_dict.get('ec2', {}).get('instances', []):
                                    if inst['id'] == resource_id:
                                        inst['imdsv2_required'] = True
                                        applied = True
                                        break

                        elif comp_type == 'rds_instance':
                            for rds in mutated_infra_dict.get('rds', {}).get('rds_instances', []):
                                if rds['id'] == resource_id:
                                    if 'publicly_accessible' in config:
                                        rds['publicly_accessible'] = config['publicly_accessible']
                                    if 'encrypted' in config:
                                        rds['encrypted'] = config['encrypted']
                                    applied = True
                                    break

                        elif comp_type == 's3_bucket':
                            for bucket in mutated_infra_dict.get('s3', {}).get('buckets', []):
                                if bucket['name'] == resource_id:
                                    bucket['is_public'] = False
                                    pub = mutated_infra_dict['s3'].get('public_buckets', [])
                                    if resource_id in pub:
                                        pub.remove(resource_id)
                                    applied = True
                                    break

                        if applied:
                            verification["method"] = "llm_simulated"
                except Exception as e:
                    logger.warning(f"unified_fix: HCL parse fallback failed: {e}")

        # Run simulation if mutation was applied
        if applied:
            try:
                mutated_infra = AWSInfrastructure(**mutated_infra_dict)
                mutated_graph = build_graph(mutated_infra)
                mutated_findings = run_all_checks(mutated_infra, mutated_graph)
                mutated_combos = find_toxic_combos(mutated_findings, mutated_graph, mutated_infra)

                # Diff findings
                mutated_finding_keys = set()
                mutated_findings_list = []
                for category in ['critical_risks', 'moderate_risks', 'low_risks', 'best_practices', 'cost_findings']:
                    for f in mutated_findings.get(category, []):
                        f_dict = f.model_dump() if hasattr(f, 'model_dump') else f
                        mutated_finding_keys.add((f_dict.get('rule_id', ''), f_dict.get('resource_id', '')))
                        mutated_findings_list.append(f_dict)

                # Findings removed
                removed_keys = original_finding_keys - mutated_finding_keys
                findings_removed = []
                for category in ['critical_risks', 'moderate_risks', 'low_risks', 'best_practices']:
                    for f in original_findings_data.get(category, []):
                        if (f.get('rule_id', ''), f.get('resource_id', '')) in removed_keys:
                            findings_removed.append({'rule_id': f.get('rule_id'), 'issue': f.get('issue'), 'severity': f.get('severity')})

                # Findings added
                added_keys = mutated_finding_keys - original_finding_keys
                findings_added = [f for f in mutated_findings_list if (f.get('rule_id', ''), f.get('resource_id', '')) in added_keys]

                # Toxic combos
                original_combo_ids = {c.get('combo_id', '') for c in original_findings_data.get('toxic_combinations', [])}
                mutated_combo_ids = {(c.get('combo_id') if isinstance(c, dict) else c.combo_id) for c in mutated_combos}
                combos_resolved = list(original_combo_ids - mutated_combo_ids)

                # Score
                mutated_scores = calculate_score(mutated_findings, total_resources, mutated_infra)
                mutated_score = mutated_scores.get('overall_risk_score', 0)
                score_delta = mutated_score - original_score

                risk_added = [f for f in findings_added if f.get('severity', '').lower() in ('critical', 'moderate')]
                safe = len(risk_added) == 0 and score_delta >= 0

                verification = {
                    "can_simulate": True,
                    "method": verification["method"],
                    "score_before": original_score,
                    "score_after": mutated_score,
                    "score_delta": score_delta,
                    "findings_removed": findings_removed,
                    "findings_added": findings_added,
                    "toxic_combos_resolved": combos_resolved,
                    "safe_to_apply": safe,
                }
            except Exception as e:
                logger.error(f"unified_fix: simulation failed: {e}")

    return {
        "verification": verification,
        "terraform": {
            "hcl": hcl,
            "filename": filename,
        },
        "attack_path": request.attack_path or [],
        "mitre": {
            "id": None,
            "name": None,
        },
    }


@app.get('/github/install-url')
def github_install_url():
    return {"url": os.getenv('GITHUB_APP_INSTALL_URL', 'https://github.com/apps/emfirge-security')}


@app.get('/github/repos')
def github_repos(installation_id: int):
    from app.github_service import _get_private_key
    import requests as req
    try:
        private_key = _get_private_key()
        app_id = int(os.getenv('GITHUB_APP_ID', '0'))
        from github import GithubIntegration
        integration = GithubIntegration(app_id, private_key)
        token = integration.get_access_token(installation_id).token
        resp = req.get(
            'https://api.github.com/installation/repositories',
            headers={'Authorization': f'token {token}', 'Accept': 'application/vnd.github.v3+json'},
            params={'per_page': 100},
            timeout=10
        )
        repos = [r['full_name'] for r in resp.json().get('repositories', [])]
        return GitHubReposResponse(repos=repos)
    except Exception as e:
        return GitHubReposResponse(repos=[])


@app.post('/github/pr', response_model=GitHubPRResponse)
def create_github_pr(request: GitHubPRRequest, http_request: Request):
    client_ip = http_request.client.host if http_request.client else 'unknown'
    _check_pr_rate_limit(client_ip)
    from app.github_service import get_github_client, search_tf_files, create_fix_pr
    from app.tf_indexer import find_resource_match, TFResource
    try:
        gh = get_github_client(request.installation_id)
        resource_id = request.finding.get('resource_id', '')
        resource_type = request.finding.get('resource_type', '')
        aws_service = request.finding.get('aws_service', '')

        # Try TF index first (context-aware)
        tf_match = None
        tf_index = get_tf_index(request.installation_id, request.repo)
        if tf_index:
            # Convert DB rows to TFResource objects for matching
            tf_resources = [
                TFResource(
                    resource_type=r['resource_type'],
                    resource_name=r['resource_name'],
                    file_path=r['file_path'],
                    line_number=r['line_number'],
                    identifiers=r.get('identifiers', {}),
                    block_content=r.get('block_content', ''),
                )
                for r in tf_index
            ]
            matched = find_resource_match(tf_resources, resource_id, resource_type, aws_service)

            # If no match on resource_id, try looking up the resource's human name
            # from the last scan data (e.g. SG ID "sg-0a1b..." → name "ssh-open-sg")
            if not matched:
                resource_name = _lookup_resource_name(resource_id, resource_type)
                if resource_name and resource_name != resource_id:
                    matched = find_resource_match(tf_resources, resource_name, resource_type, aws_service)

            if matched:
                tf_match = {
                    'file_path': matched.file_path,
                    'block_content': matched.block_content,
                    'resource_type': matched.resource_type,
                    'resource_name': matched.resource_name,
                    'line_number': matched.line_number,
                }

        # Fall back to GitHub Code Search if no TF index match
        file_path = None
        if not tf_match:
            tf_files = search_tf_files(gh, request.repo, resource_id, resource_type)
            file_path = tf_files[0] if tf_files else None

        result = create_fix_pr(gh, request.repo, request.finding, request.hcl, file_path, tf_match=tf_match)
        return GitHubPRResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post('/github/webhook')
async def github_webhook(http_request: Request):
    import hmac
    import hashlib
    body = await http_request.body()
    secret = os.getenv('GITHUB_WEBHOOK_SECRET', '')
    sig = http_request.headers.get('X-Hub-Signature-256', '')

    # Reject unsigned requests when a webhook secret is configured
    if secret and not sig:
        return {"status": "missing signature"}
    if secret and sig:
        expected = 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return {"status": "invalid signature"}
    payload = json.loads(body)
    if payload.get('action') == 'closed' and payload.get('pull_request', {}).get('merged'):
        pr_url = payload['pull_request']['html_url']
        logger.info(f"Emfirge PR merged: {pr_url}")

    # ── PULL REQUEST EVENTS — Auto-analyze .tf changes ────────────
    if payload.get('action') in ('opened', 'synchronize') and 'pull_request' in payload:
        installation_id = payload.get('installation', {}).get('id')
        repo_full_name = payload.get('repository', {}).get('full_name', '')
        pr_number = payload['pull_request']['number']
        head_sha = payload['pull_request']['head']['sha']
        head_branch = payload['pull_request']['head'].get('ref', '')

        # Skip analysis on Emfirge's own fix PRs (avoid analyzing our own fixes)
        if head_branch.startswith('emfirge/fix-'):
            logger.info(f"Skipping CI analysis on Emfirge fix branch: {head_branch}")
        elif installation_id and repo_full_name:
            import threading
            def _run_ci_on_pr():
                try:
                    from app.github_service import get_github_client, post_pr_comment, create_check_run, build_pr_comment_body
                    from app.tf_parser import parse_pr_diff, tf_change_to_component_config
                    import copy

                    gh = get_github_client(installation_id)
                    repo = gh.get_repo(repo_full_name)
                    pr = repo.get_pull(pr_number)

                    # Check if PR has .tf file changes
                    tf_changes = []
                    for file in pr.get_files():
                        if file.filename.endswith('.tf') and file.patch:
                            changes = parse_pr_diff(file.patch, file.filename)
                            tf_changes.extend(changes)

                    if not tf_changes:
                        return  # No TF changes, skip silently

                    # Convert to component configs
                    components = []
                    for change in tf_changes:
                        config = tf_change_to_component_config(change)
                        if config:
                            components.append(config)

                    if not components:
                        # TF changes exist but none map to security-relevant components
                        result = {
                            'status': 'pass',
                            'score_delta': 0,
                            'new_findings': [],
                            'resolved_findings': [],
                            'new_toxic_combos': [],
                            'summary': f'✅ {len(tf_changes)} TF resource(s) changed. No security-relevant modifications detected.',
                        }
                        comment_body = build_pr_comment_body(result)
                        post_pr_comment(gh, repo_full_name, pr_number, comment_body)
                        create_check_run(gh, repo_full_name, head_sha, 'pass', result['summary'])
                        return

                    # Load last scan
                    recent = get_recent_logs(limit=1)
                    if not recent:
                        result = {
                            'status': 'skip',
                            'score_delta': 0,
                            'new_findings': [],
                            'resolved_findings': [],
                            'new_toxic_combos': [],
                            'summary': 'No scan data available. Run a scan first to enable security checks.',
                        }
                        comment_body = build_pr_comment_body(result)
                        post_pr_comment(gh, repo_full_name, pr_number, comment_body)
                        create_check_run(gh, repo_full_name, head_sha, 'skip', result['summary'])
                        return

                    analysis_id = str(recent[0]['id'])
                    log = get_log_by_id(int(analysis_id))
                    if not log or not log.get('findings_json'):
                        return

                    findings_data = json.loads(log['findings_json']) if isinstance(log['findings_json'], str) else log['findings_json']
                    infra_dict = findings_data.get('infrastructure', {})
                    if not infra_dict:
                        return

                    # Calculate scan age
                    scan_age_hours = None
                    if log.get('timestamp'):
                        try:
                            scan_time = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                            scan_age_hours = round((datetime.utcnow() - scan_time.replace(tzinfo=None)).total_seconds() / 3600, 1)
                        except Exception:
                            pass

                    infrastructure = AWSInfrastructure(**infra_dict)

                    # Original finding keys
                    original_finding_keys = set()
                    for category in ['critical_risks', 'moderate_risks', 'low_risks', 'best_practices', 'cost_findings']:
                        for f in findings_data.get(category, []):
                            original_finding_keys.add((f.get('rule_id', ''), f.get('resource_id', '')))

                    original_score = findings_data.get('overall_risk_score', 0)
                    total_resources = findings_data.get('total_resources_scanned', 1)

                    # Apply mutations (same logic as /ci/analyze)
                    mutated_infra_dict = copy.deepcopy(infrastructure.model_dump())
                    new_nodes = []

                    for comp in components:
                        action = comp.get('tf_source', {}).get('action', 'add')
                        config = comp.get('config', {})
                        component_type = comp['component_type']
                        resource_name = comp['tf_source']['resource_name']
                        file_path_tf = comp['tf_source']['file_path']

                        if action == 'delete':
                            continue

                        if component_type == 'security_group':
                            new_sg = {
                                'id': f"pr-sg-{resource_name}",
                                'name': config.get('name', resource_name),
                                'rules': [],
                                'attached_to': [],
                            }
                            if config.get('open_to_internet'):
                                new_sg['rules'].append({
                                    'from_port': config.get('from_port', 0),
                                    'to_port': config.get('to_port', config.get('from_port', 0)),
                                    'protocol': 'tcp',
                                    'ip_ranges': ['0.0.0.0/0'],
                                })
                            mutated_infra_dict['ec2']['security_groups'].append(new_sg)
                            new_nodes.append({'id': new_sg['id'], 'type': 'security_group', 'name': resource_name, 'file': file_path_tf})

                        elif component_type == 'ec2_instance':
                            new_id = f"pr-ec2-{resource_name}"
                            mutated_infra_dict['ec2']['instances'].append({
                                'id': new_id, 'type': config.get('instance_type', 't3.micro'),
                                'sg_ids': [], 'subnet_id': config.get('subnet_id', ''),
                                'state': 'running', 'imdsv2_required': config.get('imdsv2_required', False),
                            })
                            new_nodes.append({'id': new_id, 'type': 'ec2_instance', 'name': resource_name, 'file': file_path_tf})

                        elif component_type == 'rds_instance':
                            new_id = f"pr-rds-{resource_name}"
                            mutated_infra_dict['rds']['rds_instances'].append({
                                'id': new_id, 'sg_ids': [],
                                'publicly_accessible': config.get('publicly_accessible', False),
                                'encrypted': config.get('encrypted', True),
                            })
                            new_nodes.append({'id': new_id, 'type': 'rds_instance', 'name': resource_name, 'file': file_path_tf})

                        elif component_type == 's3_bucket':
                            new_id = f"pr-s3-{resource_name}"
                            mutated_infra_dict['s3']['buckets'].append({
                                'name': new_id, 'is_public': config.get('is_public', False),
                                'has_cloudfront': False, 'policy': None, 'is_empty': True,
                            })
                            new_nodes.append({'id': new_id, 'type': 's3_bucket', 'name': resource_name, 'file': file_path_tf})

                        elif component_type == 'lambda_function':
                            new_id = f"pr-lambda-{resource_name}"
                            mutated_infra_dict['lambda_data']['functions'].append({
                                'name': new_id, 'role_arn': config.get('role_arn', ''),
                                'vpc_id': None, 'subnet_ids': [], 'secret_refs': [],
                            })
                            new_nodes.append({'id': new_id, 'type': 'lambda_function', 'name': resource_name, 'file': file_path_tf})

                    # Rebuild graph + run rules
                    mutated_infra = AWSInfrastructure(**mutated_infra_dict)
                    mutated_graph = build_graph(mutated_infra)
                    mutated_findings = run_all_checks(mutated_infra, mutated_graph)
                    mutated_combos = find_toxic_combos(mutated_findings, mutated_graph, mutated_infra)

                    # Diff findings
                    new_findings = []
                    mutated_finding_keys = set()
                    for category in ['critical_risks', 'moderate_risks', 'low_risks', 'best_practices', 'cost_findings']:
                        for f in mutated_findings.get(category, []):
                            f_dict = f.model_dump() if hasattr(f, 'model_dump') else f
                            rid = f_dict.get('rule_id', '')
                            res = f_dict.get('resource_id', '')
                            mutated_finding_keys.add((rid, res))
                            if (rid, res) not in original_finding_keys:
                                source_file = None
                                for node in new_nodes:
                                    if node['id'] in (res or ''):
                                        source_file = node['file']
                                        break
                                new_findings.append({
                                    'rule_id': rid, 'severity': f_dict.get('severity', 'Moderate'),
                                    'issue': f_dict.get('issue', ''), 'resource_id': res,
                                    'file_path': source_file, 'attack_path': f_dict.get('attack_path'),
                                })

                    # Resolved findings
                    resolved_findings = []
                    for category in ['critical_risks', 'moderate_risks', 'low_risks', 'best_practices']:
                        for f in findings_data.get(category, []):
                            if (f.get('rule_id', ''), f.get('resource_id', '')) not in mutated_finding_keys:
                                resolved_findings.append({
                                    'rule_id': f.get('rule_id', ''), 'issue': f.get('issue', ''),
                                    'severity': f.get('severity', ''), 'resource_id': f.get('resource_id', ''),
                                })

                    # Score delta
                    new_total = total_resources + len([n for n in new_nodes if n['type'] != 'security_group'])
                    mutated_scores = calculate_score(mutated_findings, new_total, mutated_infra)
                    score_delta = mutated_scores.get('overall_risk_score', 0) - original_score

                    # Toxic combos
                    original_combo_ids = {c.get('combo_id', '') for c in findings_data.get('toxic_combinations', [])}
                    new_toxic_combos = [
                        (c.get('combo_id') if isinstance(c, dict) else c.combo_id)
                        for c in mutated_combos
                        if (c.get('combo_id') if isinstance(c, dict) else c.combo_id) not in original_combo_ids
                    ]

                    # Determine status
                    critical_new = [f for f in new_findings if f.get('severity') == 'Critical']
                    if critical_new:
                        status = 'fail'
                    elif new_findings or new_toxic_combos:
                        status = 'warn'
                    elif resolved_findings:
                        status = 'pass'
                    else:
                        status = 'pass'

                    # Build summary
                    if status == 'fail':
                        summary_text = f"🚨 {len(critical_new)} critical finding(s). Score: {score_delta:+d} points."
                    elif status == 'warn':
                        summary_text = f"⚠️ {len(new_findings)} new finding(s). Score: {score_delta:+d} points."
                    elif resolved_findings:
                        summary_text = f"✅ {len(resolved_findings)} finding(s) resolved. Score: {score_delta:+d} points. This PR improves security."
                    else:
                        summary_text = f"✅ {len(components)} resource(s) simulated. No security impact."

                    if scan_age_hours and scan_age_hours > 72:
                        summary_text += f" ⚠️ Scan is {scan_age_hours:.0f}h old."

                    result = {
                        'status': status,
                        'score_delta': score_delta,
                        'new_findings': new_findings,
                        'resolved_findings': resolved_findings,
                        'new_toxic_combos': new_toxic_combos,
                        'summary': summary_text,
                        'scan_age_hours': scan_age_hours,
                    }

                    # Post comment + check run
                    comment_body = build_pr_comment_body(result)
                    post_pr_comment(gh, repo_full_name, pr_number, comment_body)
                    try:
                        create_check_run(gh, repo_full_name, head_sha, status, summary_text, comment_body)
                    except Exception as e:
                        logger.warning(f"Check run creation failed (may need 'checks:write' permission): {e}")

                    logger.info(f"CI auto-review posted on {repo_full_name}#{pr_number}: {status}")

                except Exception as e:
                    logger.error(f"Auto CI review failed for {repo_full_name}#{pr_number}: {e}")

            # Run in background thread so webhook returns quickly
            threading.Thread(target=_run_ci_on_pr, daemon=True).start()

    # Handle push events — re-index TF files if .tf files changed
    if 'commits' in payload and 'repository' in payload:
        repo_full_name = payload['repository'].get('full_name', '')
        installation_id = payload.get('installation', {}).get('id')
        if installation_id and repo_full_name:
            # Check if any .tf files were modified
            tf_changed = False
            for commit in payload.get('commits', []):
                all_files = commit.get('added', []) + commit.get('modified', []) + commit.get('removed', [])
                if any(f.endswith('.tf') for f in all_files):
                    tf_changed = True
                    break
            if tf_changed:
                try:
                    from app.github_service import get_github_client
                    from app.tf_indexer import build_index_for_installation
                    gh = get_github_client(installation_id)
                    resources = build_index_for_installation(gh, installation_id, repo_full_name)
                    save_tf_index(installation_id, repo_full_name, resources)
                    logger.info(f"Re-indexed {len(resources)} TF resources for {repo_full_name}")
                except Exception as e:
                    logger.error(f"TF re-index failed for {repo_full_name}: {e}")

    return {"status": "ok"}


# ── TF INDEXING ──────────────────────────────────────────────────

@app.post('/github/index-tf', response_model=TFIndexResponse)
def index_tf_repo(request: TFIndexRequest):
    """Manually trigger TF indexing for a repo. Called after GitHub App install."""
    from app.github_service import get_github_client
    from app.tf_indexer import build_index_for_installation
    try:
        gh = get_github_client(request.installation_id)
        resources = build_index_for_installation(gh, request.installation_id, request.repo)
        count = save_tf_index(request.installation_id, request.repo, resources)
        return TFIndexResponse(
            status="indexed",
            resources_found=count,
            repo=request.repo,
            message=f"Found {count} Terraform resources"
        )
    except Exception as e:
        return TFIndexResponse(
            status="error",
            repo=request.repo,
            message=str(e)
        )


@app.get('/github/index-status')
def tf_index_status(installation_id: int, repo: str):
    """Check TF indexing status for a repo."""
    status = get_tf_index_status(installation_id, repo)
    return TFIndexStatusResponse(
        indexed=status['indexed'],
        count=status['count'],
        last_indexed=status['last_indexed'],
        repo=repo,
    )


# ── CI/CD GATE ───────────────────────────────────────────────────

@app.post('/ci/api-key', response_model=CIAPIKeyResponse)
def create_ci_key(request: CIAPIKeyRequest):
    """Create a CI/CD API key for an installation. User stores this in GitHub Secrets."""
    api_key = create_ci_api_key(request.installation_id, request.repo)
    if not api_key:
        raise HTTPException(status_code=500, detail="Failed to create API key")
    return CIAPIKeyResponse(
        api_key=api_key,
        repo=request.repo,
        message="Store this key in your GitHub repository secrets as EMFIRGE_API_KEY"
    )


@app.get('/ci/api-keys')
def list_ci_keys(installation_id: int):
    """List CI/CD API keys for an installation (shows prefixes only)."""
    return get_ci_api_keys(installation_id)


@app.post('/ci/analyze', response_model=CIAnalyzeResponse)
def ci_analyze(request: CIAnalyzeRequest, http_request: Request):
    """
    CI/CD Gate: Analyze a PR for security impact using FULL infrastructure simulation.

    Flow:
    1. Authenticate via API key
    2. Fetch PR diff from GitHub, parse .tf changes
    3. Load last scan's infrastructure from DB
    4. For each TF resource change: deep-copy infra, mutate, rebuild graph, run all rules
    5. Diff findings (new vs original), calculate real score delta
    6. Detect new attack paths (BFS from internet)
    7. Return structured response with pass/warn/fail + findings + attack paths

    This is NOT a static lint — it simulates the PR against your actual live infrastructure.
    """
    import copy

    # Authenticate via API key
    api_key = http_request.headers.get('X-API-Key', '')
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")

    key_info = validate_ci_api_key(api_key)
    if not key_info:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")

    installation_id = key_info['installation_id']

    # Get the last scan for this account to simulate against
    analysis_id = request.analysis_id
    if not analysis_id:
        recent = get_recent_logs(limit=1)
        if recent:
            analysis_id = str(recent[0]['id'])
        else:
            return CIAnalyzeResponse(
                status="skip",
                summary="No scan data available. Run a scan first to enable CI/CD security checks.",
            )

    # Fetch the scan data
    from app.tf_parser import parse_pr_diff, tf_change_to_component_config, TF_TO_EMFIRGE_TYPE
    from app.github_service import get_github_client

    try:
        gh = get_github_client(installation_id)
        repo = gh.get_repo(request.repo)
        pr = repo.get_pull(request.pr_number)

        # Get the diff for .tf files only
        tf_changes = []
        for file in pr.get_files():
            if file.filename.endswith('.tf') and file.patch:
                changes = parse_pr_diff(file.patch, file.filename)
                tf_changes.extend(changes)

        if not tf_changes:
            return CIAnalyzeResponse(
                status="pass",
                summary="No Terraform changes detected in this PR.",
            )

        # Convert TF changes to component configs for simulation
        components = []
        for change in tf_changes:
            config = tf_change_to_component_config(change)
            if config:
                components.append(config)

        if not components:
            return CIAnalyzeResponse(
                status="pass",
                summary=f"PR modifies {len(tf_changes)} TF resources but none map to security-relevant components.",
            )

        # ── LOAD INFRASTRUCTURE FROM DB ───────────────────────────
        from app.database import SessionLocal, AnalysisLog

        log = get_log_by_id(int(analysis_id)) if analysis_id.isdigit() else {}
        if not log or not log.get('findings_json'):
            return CIAnalyzeResponse(
                status="skip",
                summary=f"Scan {analysis_id} not found or has no data.",
            )

        # Calculate scan age
        scan_age_hours = None
        if log.get('timestamp'):
            try:
                scan_time = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                scan_age_hours = round((datetime.utcnow() - scan_time.replace(tzinfo=None)).total_seconds() / 3600, 1)
            except Exception:
                pass

        findings_data = json.loads(log['findings_json']) if isinstance(log['findings_json'], str) else log['findings_json']
        infra_dict = findings_data.get('infrastructure', {})
        if not infra_dict:
            # Fallback: no infrastructure data in this scan (old format)
            return CIAnalyzeResponse(
                status="skip",
                summary="Scan data missing infrastructure snapshot. Run a new scan to enable full simulation.",
            )

        infrastructure = AWSInfrastructure(**infra_dict)

        # ── ORIGINAL FINDINGS BASELINE ────────────────────────────
        original_finding_keys = set()
        for category in ['critical_risks', 'moderate_risks', 'low_risks', 'best_practices', 'cost_findings']:
            for f in findings_data.get(category, []):
                rid = f.get('rule_id', '')
                res = f.get('resource_id', '')
                original_finding_keys.add((rid, res))

        original_score = findings_data.get('overall_risk_score', 0)
        total_resources = findings_data.get('total_resources_scanned', 1)

        # ── SIMULATE ALL CHANGES (FULL GRAPH + RULES) ─────────────
        # Deep-copy infrastructure once, apply ALL changes, then run rules once
        mutated_infra_dict = copy.deepcopy(infrastructure.model_dump())

        new_nodes = []
        for comp in components:
            action = comp.get('tf_source', {}).get('action', 'add')
            config = comp.get('config', {})
            component_type = comp['component_type']
            resource_name = comp['tf_source']['resource_name']
            file_path = comp['tf_source']['file_path']

            if action == 'delete':
                # For deletes, we'd remove from infra — skip for now (complex)
                continue

            # Apply mutation based on component type (same logic as /simulate/component)
            if component_type == 'security_group':
                # Add SG rules to existing or create new SG
                new_sg = {
                    'id': f"pr-sg-{resource_name}",
                    'name': config.get('name', resource_name),
                    'rules': [],
                    'attached_to': [],
                }
                # If open to internet, add the rule
                if config.get('open_to_internet'):
                    from_port = config.get('from_port', 0)
                    to_port = config.get('to_port', from_port)
                    new_sg['rules'].append({
                        'from_port': from_port,
                        'to_port': to_port,
                        'protocol': 'tcp',
                        'ip_ranges': ['0.0.0.0/0'],
                    })
                mutated_infra_dict['ec2']['security_groups'].append(new_sg)
                new_nodes.append({'id': new_sg['id'], 'type': 'security_group', 'name': resource_name, 'file': file_path})

            elif component_type == 'ec2_instance':
                new_id = f"pr-ec2-{resource_name}"
                mutated_infra_dict['ec2']['instances'].append({
                    'id': new_id,
                    'type': config.get('instance_type', 't3.micro'),
                    'sg_ids': [],
                    'subnet_id': config.get('subnet_id', ''),
                    'state': 'running',
                    'imdsv2_required': config.get('imdsv2_required', False),
                })
                mutated_infra_dict['ec2']['instance_count'] += 1
                mutated_infra_dict['ec2']['instance_ids'].append(new_id)
                new_nodes.append({'id': new_id, 'type': 'ec2_instance', 'name': resource_name, 'file': file_path})

            elif component_type == 'rds_instance':
                new_id = f"pr-rds-{resource_name}"
                is_public = config.get('publicly_accessible', False)
                is_encrypted = config.get('encrypted', True)
                mutated_infra_dict['rds']['rds_instances'].append({
                    'id': new_id,
                    'sg_ids': [],
                    'publicly_accessible': is_public,
                    'encrypted': is_encrypted,
                })
                mutated_infra_dict['rds']['instances'].append(new_id)
                if is_public:
                    mutated_infra_dict['rds']['publicly_accessible'].append(new_id)
                if not is_encrypted:
                    mutated_infra_dict['rds']['unencrypted_instances'].append(new_id)
                if not config.get('deletion_protection', False):
                    mutated_infra_dict['rds']['instances_without_deletion_protection'].append(new_id)
                if not config.get('multi_az', False):
                    mutated_infra_dict['rds']['multi_az_enabled'] = False
                new_nodes.append({'id': new_id, 'type': 'rds_instance', 'name': resource_name, 'file': file_path})

            elif component_type == 's3_bucket':
                new_id = f"pr-s3-{resource_name}"
                is_public = config.get('is_public', False)
                mutated_infra_dict['s3']['buckets'].append({
                    'name': new_id,
                    'is_public': is_public,
                    'has_cloudfront': False,
                    'policy': None,
                    'is_empty': True,
                })
                mutated_infra_dict['s3']['total_buckets'] += 1
                if is_public:
                    mutated_infra_dict['s3']['public_buckets'].append(new_id)
                if not config.get('versioning_enabled', True):
                    mutated_infra_dict['s3']['buckets_without_versioning'].append(new_id)
                new_nodes.append({'id': new_id, 'type': 's3_bucket', 'name': resource_name, 'file': file_path})

            elif component_type == 'lambda_function':
                new_id = f"pr-lambda-{resource_name}"
                mutated_infra_dict['lambda_data']['functions'].append({
                    'name': new_id,
                    'role_arn': config.get('role_arn', ''),
                    'vpc_id': None,
                    'subnet_ids': [],
                    'secret_refs': [],
                })
                mutated_infra_dict['lambda_data']['function_count'] += 1
                new_nodes.append({'id': new_id, 'type': 'lambda_function', 'name': resource_name, 'file': file_path})

            elif component_type == 'load_balancer':
                new_id = f"pr-alb-{resource_name}"
                new_arn = f"arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/{new_id}/0000"
                mutated_infra_dict['ec2']['load_balancers'].append({
                    'arn': new_arn,
                    'type': 'application',
                    'target_instances': [],
                })
                mutated_infra_dict['ec2']['has_load_balancer'] = True
                new_nodes.append({'id': new_arn, 'type': 'load_balancer', 'name': resource_name, 'file': file_path})

        # ── REBUILD GRAPH + RUN ALL 58 RULES ──────────────────────
        mutated_infra = AWSInfrastructure(**mutated_infra_dict)
        mutated_graph = build_graph(mutated_infra)
        mutated_bfs = bfs_from_internet(mutated_graph)

        # Run all checks on mutated infrastructure
        mutated_findings = run_all_checks(mutated_infra, mutated_graph)
        mutated_combos = find_toxic_combos(mutated_findings, mutated_graph, mutated_infra)

        # ── DIFF FINDINGS (new vs original) ───────────────────────
        new_findings = []
        for category in ['critical_risks', 'moderate_risks', 'low_risks', 'best_practices', 'cost_findings']:
            for f in mutated_findings.get(category, []):
                f_dict = f.model_dump() if hasattr(f, 'model_dump') else f
                rid = f_dict.get('rule_id', '')
                res = f_dict.get('resource_id', '')
                if (rid, res) not in original_finding_keys:
                    # Enrich with file path from the component that caused it
                    source_file = None
                    for node in new_nodes:
                        if node['id'] in (res or ''):
                            source_file = node['file']
                            break
                    new_findings.append({
                        'rule_id': rid,
                        'severity': f_dict.get('severity', 'Moderate'),
                        'issue': f_dict.get('issue', ''),
                        'resource_id': res,
                        'resource_type': f_dict.get('resource_type', ''),
                        'file_path': source_file,
                        'attack_path': f_dict.get('attack_path'),
                        'blast_radius': f_dict.get('blast_radius', 0),
                    })

        # ── RESOLVED FINDINGS (existed before, gone after mutation) ─
        # Build set of all finding keys AFTER mutation
        mutated_finding_keys = set()
        for category in ['critical_risks', 'moderate_risks', 'low_risks', 'best_practices', 'cost_findings']:
            for f in mutated_findings.get(category, []):
                f_dict = f.model_dump() if hasattr(f, 'model_dump') else f
                mutated_finding_keys.add((f_dict.get('rule_id', ''), f_dict.get('resource_id', '')))

        resolved_findings = []
        all_original_findings = []
        for category in ['critical_risks', 'moderate_risks', 'low_risks', 'best_practices']:
            all_original_findings.extend(findings_data.get(category, []))

        for f in all_original_findings:
            rid = f.get('rule_id', '')
            res = f.get('resource_id', '')
            if (rid, res) not in mutated_finding_keys:
                resolved_findings.append({
                    'rule_id': rid,
                    'issue': f.get('issue', ''),
                    'severity': f.get('severity', 'Moderate'),
                    'resource_id': res,
                })

        # ── DETECT NEW ATTACK PATHS ───────────────────────────────
        attack_paths = []
        bfs_layers = mutated_bfs.get('layers', {})
        for node in new_nodes:
            if node['id'] in bfs_layers:
                depth = bfs_layers[node['id']]
                attack_paths.append({
                    'target': node['id'],
                    'target_name': node['name'],
                    'target_type': node['type'],
                    'file_path': node['file'],
                    'depth': depth,
                    'reachable_from_internet': True,
                })

        # ── DETECT NEW TOXIC COMBOS ───────────────────────────────
        original_combo_ids = {c.get('combo_id', '') for c in findings_data.get('toxic_combinations', [])}
        new_toxic_combos = []
        for c in mutated_combos:
            combo_id = c.get('combo_id') if isinstance(c, dict) else c.combo_id
            if combo_id not in original_combo_ids:
                new_toxic_combos.append(combo_id)

        # ── CALCULATE REAL SCORE DELTA ────────────────────────────
        new_total_resources = total_resources + len([n for n in new_nodes if n['type'] != 'security_group'])
        mutated_scores = calculate_score(mutated_findings, new_total_resources, mutated_infra)
        mutated_score = mutated_scores.get('overall_risk_score', 0)
        score_delta = mutated_score - original_score

        # ── DETERMINE STATUS ──────────────────────────────────────
        critical_new = [f for f in new_findings if f.get('severity') == 'Critical']
        has_attack_paths = len(attack_paths) > 0

        if critical_new or (has_attack_paths and len(critical_new) > 0):
            status = "fail"
            parts = []
            if critical_new:
                parts.append(f"{len(critical_new)} critical finding(s)")
            if has_attack_paths:
                parts.append(f"{len(attack_paths)} new internet-reachable resource(s)")
            if new_toxic_combos:
                parts.append(f"{len(new_toxic_combos)} toxic combo(s)")
            summary = f"🚨 FAIL — {', '.join(parts)}. Score impact: {score_delta:+d} points."
        elif new_findings or new_toxic_combos:
            status = "warn"
            summary = f"⚠️ WARN — {len(new_findings)} new finding(s), {len(new_toxic_combos)} toxic combo(s). Score impact: {score_delta:+d} points."
        elif resolved_findings:
            status = "pass"
            resolved_count = len(resolved_findings)
            critical_resolved = len([f for f in resolved_findings if f.get('severity') == 'Critical'])
            parts = [f"{resolved_count} finding(s) resolved"]
            if critical_resolved:
                parts[0] = f"{resolved_count} finding(s) resolved ({critical_resolved} critical)"
            summary = f"✅ {', '.join(parts)}. Score impact: {score_delta:+d} points. This PR improves your security posture."
        else:
            status = "pass"
            summary = f"✅ PASS — {len(components)} resource(s) simulated against live infrastructure. No security impact."

        # Add scan age warning
        if scan_age_hours and scan_age_hours > 72:
            summary += f" ⚠️ Scan is {scan_age_hours:.0f}h old — consider re-scanning for accuracy."

        return CIAnalyzeResponse(
            status=status,
            score_delta=score_delta,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            new_toxic_combos=new_toxic_combos,
            summary=summary,
            scan_age_hours=scan_age_hours,
        )

    except Exception as e:
        logger.error(f"CI/CD analysis failed: {e}")
        return CIAnalyzeResponse(
            status="skip",
            summary=f"Analysis failed: {str(e)[:100]}",
        )


# ── FEEDBACK ─────────────────────────────────────────────
_feedback_request_log = {}

@app.post('/feedback')
async def submit_feedback(request: FeedbackRequest, http_request: Request):
    ip = http_request.client.host
    now = time.time()
    _feedback_request_log[ip] = [t for t in _feedback_request_log.get(ip, []) if now - t < 3600]
    if len(_feedback_request_log.get(ip, [])) >= 5:
        raise HTTPException(status_code=429, detail="Feedback rate limit reached. Try again later.")
    _feedback_request_log.setdefault(ip, []).append(now)

    if not request.message or len(request.message.strip()) < 3:
        raise HTTPException(status_code=400, detail="Message is too short.")
    if len(request.message) > 2000:
        raise HTTPException(status_code=400, detail="Message is too long (max 2000 chars).")

    fb_id = save_feedback(
        message=request.message.strip(),
        name=(request.name or '').strip()[:100],
        email=(request.email or '').strip()[:200],
        aws_account_id=(request.aws_account_id or '').strip()[:20],
        page=(request.page or '').strip()[:50],
    )
    if fb_id < 0:
        raise HTTPException(status_code=500, detail="Failed to save feedback.")
    return {"status": "ok", "id": fb_id}

@app.get('/feedback')
def list_feedback(limit: int = 50, key: str = None):
    # Admin-only: requires FEEDBACK_ADMIN_KEY to read feedback
    admin_key = os.getenv('FEEDBACK_ADMIN_KEY', '')
    if not admin_key or key != admin_key:
        raise HTTPException(status_code=403, detail='Forbidden')
    return get_feedback(limit=min(limit, 100))


@app.post('/analyze')
def analyze(credentials: AWSCredentials, request: Request, raw: bool = False):
    start_time = time.time()

    # AGENTOPS SESSION START
    session = None
    try:
        session = None  # AgentOps omitted
    except Exception:
        pass

    try:
        # ── RATE LIMITING — DAILY_SCAN_LIMIT scans per day per AWS account ──────
        # Extract account ID from role ARN — no extra API call needed
        # Role ARN format: arn:aws:iam::ACCOUNT_ID:role/RoleName
        try:
            account_id = credentials.role_arn.split(':')[4]
        except Exception:
            account_id = 'unknown'

        if account_id != 'unknown':
            # Whitelisted accounts bypass rate limiting (owner/dev accounts)
            WHITELISTED_ACCOUNTS = set(filter(None, os.getenv('WHITELISTED_ACCOUNTS', '').split(',')))
            if account_id not in WHITELISTED_ACCOUNTS:
                scan_count = get_scan_count_today(account_id)
                if scan_count >= DAILY_SCAN_LIMIT:
                    if session: session.end_session(end_state='Fail')
                    raise HTTPException(
                        status_code=429,
                        detail=f'Rate limit reached. Your AWS account has used {scan_count}/{DAILY_SCAN_LIMIT} free scans today. Limit resets at midnight UTC.'
                    )

        # STEP 1 — Collect infrastructure data (demo or real)
        from app.demo_seed import is_demo_arn, get_demo_infrastructure
        if is_demo_arn(credentials.role_arn):
            infrastructure = get_demo_infrastructure()
        else:
            infrastructure = collect_infrastructure(credentials)

        # STEP 1.5 — Build infrastructure graph for relationship-aware rules
        graph = build_graph(infrastructure)

        # STEP 2 — Run all risk checks (with graph for smarter severity detection)
        findings = run_all_checks(infrastructure, graph)

        # STEP 2.5 — Enhance findings with attack path and blast radius analysis
        from app.egraph import find_attack_path, calculate_blast_radius
        
        # Process critical and moderate risks
        for finding_list in [findings.get('critical_risks', []), findings.get('moderate_risks', [])]:
            for finding in finding_list:
                if finding.resource_id:
                    # Calculate attack path
                    attack_path = find_attack_path(graph, finding.resource_id)

                    # Fallback for SG-type findings: SG nodes have no inbound graph edges
                    # so find_attack_path returns empty. Re-run from the first attached instance.
                    if not attack_path and finding.resource_type == 'security_group':
                        sg_id = finding.resource_id
                        for sg in infrastructure.ec2.security_groups:
                            # Handle both dict and Pydantic model formats
                            _id = sg['id'] if isinstance(sg, dict) else sg.id
                            if _id == sg_id:
                                _attached = sg.get('attached_to', []) if isinstance(sg, dict) else sg.attached_to
                                if _attached:
                                    instance_path = find_attack_path(graph, _attached[0])
                                    if instance_path:
                                        # Prepend the SG node itself to the path
                                        sg_node = graph.get_node(sg_id)
                                        if sg_node:
                                            attack_path = [sg_node] + instance_path
                                        else:
                                            attack_path = instance_path
                                break

                    finding.attack_path = [node['id'] for node in attack_path] if attack_path else []
                    
                    # Calculate blast radius
                    blast_radius_result = calculate_blast_radius(graph, finding.resource_id)
                    finding.blast_radius = blast_radius_result['count']

        # STEP 2.75 — Detect toxic combinations of co-existing findings
        toxic_combinations = find_toxic_combos(findings, graph, infrastructure)

        # STEP 2.8 — MITRE ATT&CK enrichment
        from app.mitre import MITRE_MAPPING
        critical_risks = findings.get('critical_risks', [])
        moderate_risks = findings.get('moderate_risks', [])
        best_practices = findings.get('best_practices', [])
        cost_findings  = findings.get('cost_findings', [])
        all_findings_for_mitre = critical_risks + moderate_risks + best_practices + cost_findings
        for finding in all_findings_for_mitre:
            if finding.rule_id and finding.rule_id in MITRE_MAPPING:
                technique_id, technique_name = MITRE_MAPPING[finding.rule_id]
                finding.mitre_technique_id = technique_id
                finding.mitre_technique_name = technique_name

        # STEP 3 — Calculate weighted scores
        # total_resources must be computed here so it can be passed to calculate_score
        total_resources = (
            infrastructure.ec2.instance_count +
            len(infrastructure.ec2.security_groups) +
            len(infrastructure.ec2.ebs_volumes) +
            len(infrastructure.ec2.elastic_ips) +
            infrastructure.s3.total_buckets +
            len(infrastructure.rds.instances) +
            len(infrastructure.iam.iam_users) +
            (1 if infrastructure.cloudtrail.is_enabled else 0) +
            infrastructure.lambda_data.function_count +
            infrastructure.secrets_manager.total_secrets +
            (1 if infrastructure.guardduty.is_enabled else 0) +
            infrastructure.vpc.total_vpcs +
            len(infrastructure.vpc.subnets) +
            infrastructure.kms.total_cmks +
            infrastructure.sns.total_topics +
            infrastructure.ecs.total_task_definitions
        )
        scores = calculate_score(findings, total_resources, infrastructure)

        # Build local warnings list — starts with collector warnings (skipped services),
        # backend failures (Gemini, S3, DB) are appended below
        warnings = list(infrastructure.warnings)

        # STEP 4 — Get AI explanation from Gemini (skipped in raw mode for MCP callers)
        if _is_raw_mode(request, raw):
            ai_result = {
                'ai_summary': '',
                'recommended_improvements': [],
                'priority_actions': [],
                'latency_ms': 0,
            }
        else:
            try:
                ai_result = generate_explanation(
                    findings,
                    scores['overall_risk_score'],
                    credentials.region
                )
            except Exception as gemini_error:
                print(f'Gemini failed: {gemini_error}')
                warnings.append('AI summary unavailable — Gemini failed. Priority actions may be empty.')
                ai_result = {
                    'ai_summary': 'AI summary temporarily unavailable. Please review the findings manually.',
                    'recommended_improvements': [
                        'Review all critical risks immediately',
                        'Fix security group rules',
                        'Enable MFA on all IAM users',
                        'Enable CloudTrail for audit logging'
                    ],
                    'priority_actions': [],
                    'latency_ms': 0
                }

        # Generate unique ID
        analysis_id = str(uuid.uuid4())

        # Calculate scan duration
        scan_duration = round(time.time() - start_time, 2)

        # STEP 5 — Save report to S3
        report_data = {
            'analysis_id': analysis_id,
            'timestamp': datetime.utcnow().isoformat(),
            'region_analyzed': credentials.region,
            'overall_risk_score': scores['overall_risk_score'],
            'overall_risk_level': scores['overall_risk_level'],
            'security_score': scores['security_score'],
            'availability_score': scores['availability_score'],
            'disaster_recovery_score': scores['disaster_recovery_score'],
            'cost_score': scores['cost_score'],
            'cost_level': scores['cost_level'],
            'maturity_score': scores['maturity_score'],
            'maturity_bonus': scores['maturity_bonus'],
            'maturity_checks_passed': scores['maturity_checks_passed'],
            'critical_risks': [r.dict() for r in findings.get('critical_risks', [])],
            'moderate_risks': [r.dict() for r in findings.get('moderate_risks', [])],
            'low_risks': [r.dict() for r in findings.get('low_risks', [])],
            'cost_findings': [r.dict() for r in findings.get('cost_findings', [])],
            'best_practices': [r.dict() for r in findings.get('best_practices', [])],
            'toxic_combinations': [c.dict() for c in toxic_combinations],
            'ai_summary': ai_result['ai_summary'],
            'recommended_improvements': ai_result['recommended_improvements'],
            'priority_actions': ai_result.get('priority_actions', []),
            'warnings': warnings,
            'total_resources_scanned': total_resources,
            'scan_duration_seconds': scan_duration,
            'infrastructure': infrastructure.dict()  # Store infrastructure data for graph endpoint
        }

        # STEP 5 + 6 — Save to S3 and DB concurrently (Gemini already done, report_data is ready)
        from concurrent.futures import ThreadPoolExecutor

        def _save_s3():
            try:
                key = save_report(analysis_id, report_data)
                return get_report_url(key), None
            except Exception as e:
                return '', e

        def _save_db():
            for attempt in range(2):
                try:
                    result = save_analysis({
                        'region_analyzed': credentials.region,
                        'ec2_count': infrastructure.ec2.instance_count,
                        'risk_score': scores['overall_risk_score'],
                        'risk_level': scores['overall_risk_level'],
                        'security_score': scores['security_score'],
                        'availability_score': scores['availability_score'],
                        'cost_score': scores['cost_score'],
                        'critical_count': len(findings.get('critical_risks', [])),
                        'moderate_count': len(findings.get('moderate_risks', [])),
                        'findings_json': report_data,
                        'llm_response': ai_result['ai_summary'],
                        'latency_ms': int(scan_duration * 1000),
                        'prompt_version': 'v3.0',
                        'aws_account_id': account_id,
                    })
                    return result, None
                except Exception as e:
                    if attempt == 0:
                        time.sleep(2)
                        continue
                    return None, e

        with ThreadPoolExecutor(max_workers=2) as executor:
            s3_future = executor.submit(_save_s3)
            db_future = executor.submit(_save_db)
            report_url, s3_error = s3_future.result()
            db_result, db_error = db_future.result()

        if s3_error:
            print(f'S3 save failed: {s3_error}')
            warnings.append('Report could not be saved to S3. Download link unavailable.')

        if db_error:
            print(f'Database save failed: {db_error}')
        elif db_result == -1:
            warnings.append('Scan result could not be saved to database. Graph will not be available for this scan.')

        # AGENTOPS SESSION END
        if session: session.end_session(end_state='Success')

        # STEP 6.5 — Drift detection (never fails the scan)
        try:
            if db_result and db_result != -1:
                prev = get_previous_scan_for_account(account_id, exclude_id=db_result)
                if prev and prev.get('findings_json'):
                    prev_report = json.loads(prev['findings_json']) if isinstance(prev['findings_json'], str) else prev['findings_json']
                    prev_all = prev_report.get('critical_risks', []) + prev_report.get('moderate_risks', [])
                    curr_all = [f.dict() for f in critical_risks + moderate_risks]
                    new_f, fixed_f, _severity_changed = compare_findings(curr_all, prev_all)
                    logger.info(f"Drift: {len(new_f)} new, {len(fixed_f)} fixed vs scan {prev['id']}")
                    logger.info(f"Drift new_f: {[{'rule_id': f.get('rule_id'), 'resource_id': f.get('resource_id'), 'severity': f.get('severity')} for f in new_f]}")
                    logger.info(f"Drift fixed_f: {[{'rule_id': f.get('rule_id'), 'resource_id': f.get('resource_id'), 'severity': f.get('severity')} for f in fixed_f]}")
                    drift_rows = []
                    for f in new_f:
                        drift_rows.append({'aws_account_id': account_id, 'change_type': 'new_finding',
                            'rule_id': f.get('rule_id'), 'resource_id': f.get('resource_id'),
                            'issue': f.get('issue'), 'severity': f.get('severity'),
                            'mitre_technique_id': f.get('mitre_technique_id'),
                            'current_scan_id': db_result, 'previous_scan_id': prev['id']})
                    for f in fixed_f:
                        drift_rows.append({'aws_account_id': account_id, 'change_type': 'finding_fixed',
                            'rule_id': f.get('rule_id'), 'resource_id': f.get('resource_id'),
                            'issue': f.get('issue'), 'severity': f.get('severity'),
                            'current_scan_id': db_result, 'previous_scan_id': prev['id']})
                    if drift_rows:
                        save_drift_events(drift_rows)
                        new_crit = sum(1 for e in drift_rows if e['change_type'] == 'new_finding' and e.get('severity') == 'Critical')
                        fixed_count = sum(1 for e in drift_rows if e['change_type'] == 'finding_fixed')
                        if new_crit > 0:
                            warnings.append(f"⚠️  Drift: {new_crit} new critical finding(s) detected since last scan")
                        if fixed_count > 0:
                            warnings.append(f"✅ Drift: {fixed_count} finding(s) resolved since last scan")
        except Exception as drift_err:
            logger.warning(f"Drift detection skipped: {drift_err}")
            print(f"DRIFT ERROR: {drift_err}")

        # STEP 6.7 — Simulation baseline
        from app.models import SimulationBaseline
        public_count = 0
        try:
            if graph.get_node("INTERNET"):
                public_count = len(graph.get_outbound("INTERNET"))
        except Exception:
            pass
        sim_baseline = SimulationBaseline(
            public_resource_count=public_count,
            rds_multi_az=infrastructure.rds.multi_az_enabled if infrastructure.rds else False,
            rds_instance_count=len(infrastructure.rds.rds_instances) if infrastructure.rds else 0,
            ec2_instance_count=len(infrastructure.ec2.instances) if infrastructure.ec2 else 0,
            lambda_function_count=len(infrastructure.lambda_data.functions) if infrastructure.lambda_data else 0,
            critical_count=len(critical_risks),
            moderate_count=len(moderate_risks),
            maturity_score=scores.get('maturity_score', 0),
        )

        # STEP 7 — Return complete response
        return AnalysisResponse(
            analysis_id=analysis_id,
            timestamp=datetime.utcnow().isoformat(),
            region_analyzed=credentials.region,
            overall_risk_score=scores['overall_risk_score'],
            overall_risk_level=scores['overall_risk_level'],
            security_score=scores['security_score'],
            availability_score=scores['availability_score'],
            disaster_recovery_score=scores['disaster_recovery_score'],
            cost_score=scores['cost_score'],
            cost_level=scores['cost_level'],
            maturity_score=scores['maturity_score'],
            maturity_bonus=scores['maturity_bonus'],
            maturity_checks_passed=scores['maturity_checks_passed'],
            simulation_baseline=sim_baseline,
            critical_risks=findings.get('critical_risks', []),
            moderate_risks=findings.get('moderate_risks', []),
            best_practices=findings.get('best_practices', []),
            cost_findings=findings.get('cost_findings', []),
            toxic_combinations=toxic_combinations,
            ai_summary=ai_result['ai_summary'],
            recommended_improvements=ai_result['recommended_improvements'],
            priority_actions=ai_result.get('priority_actions', []),
            warnings=warnings,
            total_resources_scanned=total_resources,
            scan_duration_seconds=scan_duration,
            report_url=report_url
        )

    except ValueError as e:
        if session: session.end_session(end_state='Fail')
        raise HTTPException(status_code=400, detail=str(e))

    except HTTPException:
        if session: session.end_session(end_state='Fail')
        raise

    except NoCredentialsError:
        if session: session.end_session(end_state='Fail')
        raise HTTPException(
            status_code=400,
            detail='AWS credentials not found. Please check your server configuration.'
        )

    except ClientError as e:
        if session: session.end_session(end_state='Fail')
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            raise HTTPException(status_code=400, detail='Could not assume the IAM role. Make sure you deployed the Emfirge CloudFormation stack correctly.')
        else:
            raise HTTPException(status_code=400, detail=f'AWS error: {e.response["Error"]["Message"]}')

    except Exception as e:
        if session: session.end_session(end_state='Fail')
        raise HTTPException(status_code=500, detail=f'Server error: {str(e)}')


# ── SSE STREAMING ANALYZE ENDPOINT ────────────────────────────────
# Bypasses Vercel's 30s proxy timeout by streaming progress events.
# Same logic as /analyze but wrapped in an SSE generator.

@app.post('/analyze/stream')
async def analyze_stream(credentials: AWSCredentials, request: Request, raw: bool = False):
    """
    SSE streaming version of /analyze. Sends progress events as each collector
    completes, then emits the full AnalysisResponse as the final event.

    Events:
      event: progress  — {"step": "collecting", "service": "EC2", "status": "done"}
      event: progress  — {"step": "analyzing", "detail": "Running rules..."}
      event: progress  — {"step": "saving", "detail": "Saving report..."}
      event: complete  — {<full AnalysisResponse>}
      event: error     — {"message": "..."}

    Streaming responses bypass Vercel's 30s proxy timeout (up to 5 min).
    """
    import threading
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from app.demo_seed import is_demo_arn, get_demo_infrastructure
    from app.egraph import find_attack_path, calculate_blast_radius, find_critical_resources
    from app.mitre import MITRE_MAPPING
    from app.models import SimulationBaseline

    start_time = time.time()

    # ── RATE LIMITING — same as /analyze ──────────────────────────
    try:
        account_id = credentials.role_arn.split(':')[4]
    except Exception:
        account_id = 'unknown'

    if account_id != 'unknown':
        WHITELISTED_ACCOUNTS = set(filter(None, os.getenv('WHITELISTED_ACCOUNTS', '').split(',')))
        if account_id not in WHITELISTED_ACCOUNTS:
            scan_count = get_scan_count_today(account_id)
            if scan_count >= DAILY_SCAN_LIMIT:
                raise HTTPException(
                    status_code=429,
                    detail=f'Rate limit reached. Your AWS account has used {scan_count}/{DAILY_SCAN_LIMIT} free scans today. Limit resets at midnight UTC.'
                )

    async def scan_stream():
        import asyncio

        def _emit(event: str, data: dict) -> str:
            return f"event: {event}\ndata: {json.dumps(data)}\n\n"

        try:
            # ── STEP 1: Collect infrastructure ────────────────────
            yield _emit("progress", {"step": "collecting", "service": "starting", "status": "in_progress", "detail": "Assuming IAM role..."})

            if is_demo_arn(credentials.role_arn):
                infrastructure = get_demo_infrastructure()
                yield _emit("progress", {"step": "collecting", "service": "demo", "status": "done", "detail": "Demo data loaded"})
            else:
                # Inline collector with per-service progress events
                from botocore.exceptions import ClientError as _ClientError
                from botocore.config import Config as _BotoConfig
                from app.aws_collector import (
                    collect_ec2, collect_s3, collect_rds, collect_iam,
                    collect_cloudtrail, collect_cost, collect_cloudwatch,
                    collect_guardduty, collect_lambda, collect_secrets_manager,
                    collect_vpc, collect_kms, collect_config, collect_sns,
                    collect_ecs, collect_waf, BOTO_CONFIG
                )
                from app.models import (
                    EC2Data, S3Data, RDSData, IAMData, CloudTrailData,
                    CostData, CloudWatchData, GuardDutyData, LambdaData,
                    SecretsManagerData, VPCData, KMSData, ConfigData,
                    SNSData, ECSData, WAFData
                )

                # Assume role
                try:
                    sts = boto3.client('sts', config=BOTO_CONFIG)
                    assumed = sts.assume_role(
                        RoleArn=credentials.role_arn,
                        RoleSessionName='EmfirgeSecurityScan',
                        ExternalId='aws-risk-agent',
                        DurationSeconds=3600
                    )
                    key = assumed['Credentials']['AccessKeyId']
                    secret = assumed['Credentials']['SecretAccessKey']
                    token = assumed['Credentials']['SessionToken']
                except _ClientError as e:
                    code = e.response['Error']['Code']
                    if code == 'AccessDenied':
                        yield _emit("error", {"message": "Could not assume the IAM role. Make sure you deployed the Emfirge CloudFormation stack correctly."})
                        return
                    else:
                        yield _emit("error", {"message": f"Role assumption failed: {e.response['Error']['Message']}"})
                        return
                except Exception as e:
                    yield _emit("error", {"message": f"Could not connect to AWS: {str(e)}"})
                    return

                yield _emit("progress", {"step": "collecting", "service": "sts", "status": "done", "detail": "Role assumed successfully"})

                # Parallel collection with progress tracking
                warnings = []
                warnings_lock = threading.Lock()
                results = {}
                completed_count = 0

                collectors = {
                    'ec2': collect_ec2, 's3': collect_s3, 'rds': collect_rds,
                    'iam': collect_iam, 'cloudtrail': collect_cloudtrail,
                    'cost': collect_cost, 'cloudwatch': collect_cloudwatch,
                    'guardduty': collect_guardduty, 'lambda': collect_lambda,
                    'secrets_manager': collect_secrets_manager, 'vpc': collect_vpc,
                    'kms': collect_kms, 'config': collect_config,
                    'sns': collect_sns, 'ecs': collect_ecs, 'waf': collect_waf,
                }

                defaults = {
                    'ec2': EC2Data(), 's3': S3Data(), 'rds': RDSData(),
                    'iam': IAMData(), 'cloudtrail': CloudTrailData(),
                    'cost': CostData(), 'cloudwatch': CloudWatchData(),
                    'guardduty': GuardDutyData(), 'lambda': LambdaData(),
                    'secrets_manager': SecretsManagerData(), 'vpc': VPCData(),
                    'kms': KMSData(), 'config': ConfigData(),
                    'sns': SNSData(), 'ecs': ECSData(), 'waf': WAFData(),
                }

                def safe_collect(name, fn):
                    local_warnings = []
                    result = fn(key, secret, token, credentials.region, local_warnings)
                    if local_warnings:
                        with warnings_lock:
                            warnings.extend(local_warnings)
                    return name, result

                # Run collectors in thread pool, yield progress as each completes
                loop = asyncio.get_event_loop()
                # Stagger groups to reduce AWS API throttling
                _STREAM_GROUPS = [
                    ['ec2', 'rds', 'cloudtrail', 'kms'],
                    ['s3', 'guardduty', 'sns'],
                    ['iam', 'cost', 'cloudwatch', 'config'],
                    ['lambda', 'vpc', 'ecs', 'waf'],
                    ['secrets_manager'],
                ]
                import time as _t
                with ThreadPoolExecutor(max_workers=16) as executor:
                    future_to_name = {}
                    for _gi, _group in enumerate(_STREAM_GROUPS):
                        for name in _group:
                            if name in collectors:
                                future = executor.submit(safe_collect, name, collectors[name])
                                future_to_name[future] = name
                        if _gi < len(_STREAM_GROUPS) - 1:
                            _t.sleep(0.2)
                    # Safety: ungrouped collectors
                    _grouped = {n for g in _STREAM_GROUPS for n in g}
                    for name, fn in collectors.items():
                        if name not in _grouped:
                            future = executor.submit(safe_collect, name, fn)
                            future_to_name[future] = name
                    for future in as_completed(future_to_name):
                        name = future_to_name[future]
                        try:
                            _, result = future.result(timeout=20)
                            results[name] = result
                        except TimeoutError:
                            msg = f'{name} collector timed out — results excluded'
                            warnings.append(msg)
                            results[name] = defaults[name]
                        except Exception as e:
                            results[name] = defaults[name]

                        completed_count += 1
                        yield _emit("progress", {
                            "step": "collecting",
                            "service": name,
                            "status": "done",
                            "completed": completed_count,
                            "total": len(collectors),
                            "detail": f"Collected {name} ({completed_count}/{len(collectors)})"
                        })

                from app.models import AWSInfrastructure as _AWSInfra
                infrastructure = _AWSInfra(
                    ec2=results['ec2'], s3=results['s3'], rds=results['rds'],
                    iam=results['iam'], cloudtrail=results['cloudtrail'],
                    cost=results['cost'], cloudwatch=results['cloudwatch'],
                    guardduty=results['guardduty'], lambda_data=results['lambda'],
                    secrets_manager=results['secrets_manager'], vpc=results['vpc'],
                    kms=results['kms'], config=results['config'],
                    sns=results['sns'], ecs=results['ecs'], waf=results['waf'],
                    region=credentials.region, warnings=warnings
                )

            # ── STEP 2: Build graph + run rules ───────────────────
            yield _emit("progress", {"step": "analyzing", "detail": "Building infrastructure graph..."})
            graph = build_graph(infrastructure)

            yield _emit("progress", {"step": "analyzing", "detail": "Running 61 security rules..."})
            findings = run_all_checks(infrastructure, graph)

            # Enrich findings with attack paths + blast radius
            for finding_list in [findings.get('critical_risks', []), findings.get('moderate_risks', [])]:
                for finding in finding_list:
                    if finding.resource_id:
                        attack_path = find_attack_path(graph, finding.resource_id)
                        if not attack_path and finding.resource_type == 'security_group':
                            sg_id = finding.resource_id
                            for sg in infrastructure.ec2.security_groups:
                                _id = sg['id'] if isinstance(sg, dict) else sg.id
                                if _id == sg_id:
                                    _attached = sg.get('attached_to', []) if isinstance(sg, dict) else sg.attached_to
                                    if _attached:
                                        instance_path = find_attack_path(graph, _attached[0])
                                        if instance_path:
                                            sg_node = graph.get_node(sg_id)
                                            attack_path = ([sg_node] + instance_path) if sg_node else instance_path
                                    break
                        finding.attack_path = [node['id'] for node in attack_path] if attack_path else []
                        blast_radius_result = calculate_blast_radius(graph, finding.resource_id)
                        finding.blast_radius = blast_radius_result['count']

            yield _emit("progress", {"step": "analyzing", "detail": "Detecting toxic combinations..."})
            toxic_combinations = find_toxic_combos(findings, graph, infrastructure)

            # MITRE enrichment
            critical_risks = findings.get('critical_risks', [])
            moderate_risks = findings.get('moderate_risks', [])
            low_risks = findings.get('low_risks', [])
            best_practices = findings.get('best_practices', [])
            cost_findings = findings.get('cost_findings', [])
            for finding in critical_risks + moderate_risks + low_risks + best_practices + cost_findings:
                if finding.rule_id and finding.rule_id in MITRE_MAPPING:
                    technique_id, technique_name = MITRE_MAPPING[finding.rule_id]
                    finding.mitre_technique_id = technique_id
                    finding.mitre_technique_name = technique_name

            # ── STEP 3: Calculate scores ──────────────────────────
            yield _emit("progress", {"step": "analyzing", "detail": "Calculating risk scores..."})
            total_resources = (
                infrastructure.ec2.instance_count +
                len(infrastructure.ec2.security_groups) +
                len(infrastructure.ec2.ebs_volumes) +
                len(infrastructure.ec2.elastic_ips) +
                infrastructure.s3.total_buckets +
                len(infrastructure.rds.instances) +
                len(infrastructure.iam.iam_users) +
                (1 if infrastructure.cloudtrail.is_enabled else 0) +
                infrastructure.lambda_data.function_count +
                infrastructure.secrets_manager.total_secrets +
                (1 if infrastructure.guardduty.is_enabled else 0) +
                infrastructure.vpc.total_vpcs +
                len(infrastructure.vpc.subnets) +
                infrastructure.kms.total_cmks +
                infrastructure.sns.total_topics +
                infrastructure.ecs.total_task_definitions
            )
            scores = calculate_score(findings, total_resources, infrastructure)

            local_warnings = list(infrastructure.warnings)

            # ── STEP 4: AI explanation (skipped in raw mode for MCP callers) ──
            if _is_raw_mode(request, raw):
                yield _emit("progress", {"step": "ai", "detail": "Skipping AI summary (raw mode)"})
                ai_result = {
                    'ai_summary': '',
                    'recommended_improvements': [],
                    'priority_actions': [],
                    'latency_ms': 0,
                }
            else:
                yield _emit("progress", {"step": "ai", "detail": "Generating AI advisory..."})
                try:
                    ai_result = generate_explanation(findings, scores['overall_risk_score'], credentials.region)
                except Exception as gemini_error:
                    logger.warning(f'Gemini failed in stream: {gemini_error}')
                    local_warnings.append('AI summary unavailable — Gemini failed.')
                    ai_result = {
                        'ai_summary': 'AI summary temporarily unavailable.',
                        'recommended_improvements': ['Review all critical risks immediately'],
                        'priority_actions': [],
                        'latency_ms': 0
                    }

            # ── STEP 5: Save to S3 + DB ───────────────────────────
            yield _emit("progress", {"step": "saving", "detail": "Saving report..."})
            analysis_id = str(uuid.uuid4())
            scan_duration = round(time.time() - start_time, 2)

            report_data = {
                'analysis_id': analysis_id,
                'timestamp': datetime.utcnow().isoformat(),
                'region_analyzed': credentials.region,
                'overall_risk_score': scores['overall_risk_score'],
                'overall_risk_level': scores['overall_risk_level'],
                'security_score': scores['security_score'],
                'availability_score': scores['availability_score'],
                'disaster_recovery_score': scores['disaster_recovery_score'],
                'cost_score': scores['cost_score'],
                'cost_level': scores['cost_level'],
                'maturity_score': scores['maturity_score'],
                'maturity_bonus': scores['maturity_bonus'],
                'maturity_checks_passed': scores['maturity_checks_passed'],
                'critical_risks': [r.dict() for r in critical_risks],
                'moderate_risks': [r.dict() for r in moderate_risks],
                'low_risks': [r.dict() for r in low_risks],
                'cost_findings': [r.dict() for r in cost_findings],
                'best_practices': [r.dict() for r in best_practices],
                'toxic_combinations': [c.dict() for c in toxic_combinations],
                'ai_summary': ai_result['ai_summary'],
                'recommended_improvements': ai_result['recommended_improvements'],
                'priority_actions': ai_result.get('priority_actions', []),
                'warnings': local_warnings,
                'total_resources_scanned': total_resources,
                'scan_duration_seconds': scan_duration,
                'infrastructure': infrastructure.dict()
            }

            # Save S3 + DB concurrently
            from concurrent.futures import ThreadPoolExecutor as _TPE

            def _save_s3():
                try:
                    s3_key = save_report(analysis_id, report_data)
                    return get_report_url(s3_key), None
                except Exception as e:
                    return '', e

            def _save_db():
                for attempt in range(2):
                    try:
                        result = save_analysis({
                            'region_analyzed': credentials.region,
                            'ec2_count': infrastructure.ec2.instance_count,
                            'risk_score': scores['overall_risk_score'],
                            'risk_level': scores['overall_risk_level'],
                            'security_score': scores['security_score'],
                            'availability_score': scores['availability_score'],
                            'cost_score': scores['cost_score'],
                            'critical_count': len(critical_risks),
                            'moderate_count': len(moderate_risks),
                            'findings_json': report_data,
                            'llm_response': ai_result['ai_summary'],
                            'latency_ms': int(scan_duration * 1000),
                            'prompt_version': 'v3.0',
                            'aws_account_id': account_id,
                        })
                        return result, None
                    except Exception as e:
                        if attempt == 0:
                            time.sleep(2)
                            continue
                        return None, e

            with _TPE(max_workers=2) as executor:
                s3_future = executor.submit(_save_s3)
                db_future = executor.submit(_save_db)
                report_url, s3_error = s3_future.result()
                db_result, db_error = db_future.result()

            if s3_error:
                local_warnings.append('Report could not be saved to S3.')
            if db_error:
                logger.warning(f'DB save failed in stream: {db_error}')
            elif db_result == -1:
                local_warnings.append('Scan result could not be saved to database.')

            # ── Drift detection ───────────────────────────────────
            try:
                if db_result and db_result != -1:
                    prev = get_previous_scan_for_account(account_id, exclude_id=db_result)
                    if prev and prev.get('findings_json'):
                        prev_report = json.loads(prev['findings_json']) if isinstance(prev['findings_json'], str) else prev['findings_json']
                        prev_all = prev_report.get('critical_risks', []) + prev_report.get('moderate_risks', [])
                        curr_all = [f.dict() for f in critical_risks + moderate_risks]
                        new_f, fixed_f, _severity_changed = compare_findings(curr_all, prev_all)
                        drift_rows = []
                        for f in new_f:
                            drift_rows.append({'aws_account_id': account_id, 'change_type': 'new_finding',
                                'rule_id': f.get('rule_id'), 'resource_id': f.get('resource_id'),
                                'issue': f.get('issue'), 'severity': f.get('severity'),
                                'mitre_technique_id': f.get('mitre_technique_id'),
                                'current_scan_id': db_result, 'previous_scan_id': prev['id']})
                        for f in fixed_f:
                            drift_rows.append({'aws_account_id': account_id, 'change_type': 'finding_fixed',
                                'rule_id': f.get('rule_id'), 'resource_id': f.get('resource_id'),
                                'issue': f.get('issue'), 'severity': f.get('severity'),
                                'current_scan_id': db_result, 'previous_scan_id': prev['id']})
                        if drift_rows:
                            save_drift_events(drift_rows)
                            new_crit = sum(1 for e in drift_rows if e['change_type'] == 'new_finding' and e.get('severity') == 'Critical')
                            fixed_count = sum(1 for e in drift_rows if e['change_type'] == 'finding_fixed')
                            if new_crit > 0:
                                local_warnings.append(f"⚠️  Drift: {new_crit} new critical finding(s) detected since last scan")
                            if fixed_count > 0:
                                local_warnings.append(f"✅ Drift: {fixed_count} finding(s) resolved since last scan")
            except Exception as drift_err:
                logger.warning(f"Drift detection skipped in stream: {drift_err}")

            # ── Simulation baseline ───────────────────────────────
            public_count = 0
            try:
                if graph.get_node("INTERNET"):
                    public_count = len(graph.get_outbound("INTERNET"))
            except Exception:
                pass
            sim_baseline = SimulationBaseline(
                public_resource_count=public_count,
                rds_multi_az=infrastructure.rds.multi_az_enabled if infrastructure.rds else False,
                rds_instance_count=len(infrastructure.rds.rds_instances) if infrastructure.rds else 0,
                ec2_instance_count=len(infrastructure.ec2.instances) if infrastructure.ec2 else 0,
                lambda_function_count=len(infrastructure.lambda_data.functions) if infrastructure.lambda_data else 0,
                critical_count=len(critical_risks),
                moderate_count=len(moderate_risks),
                maturity_score=scores.get('maturity_score', 0),
            )

            # ── FINAL: Emit complete response ─────────────────────
            final_response = {
                'analysis_id': analysis_id,
                'timestamp': datetime.utcnow().isoformat(),
                'region_analyzed': credentials.region,
                'overall_risk_score': scores['overall_risk_score'],
                'overall_risk_level': scores['overall_risk_level'],
                'security_score': scores['security_score'],
                'availability_score': scores['availability_score'],
                'disaster_recovery_score': scores['disaster_recovery_score'],
                'cost_score': scores['cost_score'],
                'cost_level': scores['cost_level'],
                'maturity_score': scores['maturity_score'],
                'maturity_bonus': scores['maturity_bonus'],
                'maturity_checks_passed': scores['maturity_checks_passed'],
                'simulation_baseline': sim_baseline.dict(),
                'critical_risks': [r.dict() for r in critical_risks],
                'moderate_risks': [r.dict() for r in moderate_risks],
                'low_risks': [r.dict() for r in low_risks],
                'best_practices': [r.dict() for r in best_practices],
                'cost_findings': [r.dict() for r in cost_findings],
                'toxic_combinations': [c.dict() for c in toxic_combinations],
                'ai_summary': ai_result['ai_summary'],
                'recommended_improvements': ai_result['recommended_improvements'],
                'priority_actions': ai_result.get('priority_actions', []),
                'warnings': local_warnings,
                'total_resources_scanned': total_resources,
                'scan_duration_seconds': scan_duration,
                'report_url': report_url or ''
            }

            yield _emit("complete", final_response)
            # Extra newline to ensure Vercel/proxies flush the final event
            yield "\n"

        except Exception as e:
            logger.error(f"analyze/stream error: {e}")
            yield _emit("error", {"message": str(e)})

    return StreamingResponse(
        scan_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


# ── COMPONENT SIMULATION ENDPOINT ─────────────────────────────────
# Deterministic mutation: Python mutates graph, Claude only writes prose.

@app.post('/simulate/component')
def simulate_component(request: ComponentRequest, http_request: Request):
    """
    Simulate adding/modifying a component in the infrastructure.
    
    1. Load infrastructure from DB
    2. Deep-copy and mutate based on component config
    3. Rebuild graph, run BFS, run all checks
    4. Diff findings (new vs original)
    5. Calculate risk delta
    6. Call Claude Haiku for narrative prose
    7. Return structured response
    
    Shares rate limits with /simulate (10/min per IP, 3/day per account).
    NO side effects — no drift events, no analysis saves.
    """
    import copy
    import anthropic as anthropic_lib

    # ── RATE LIMIT: 10/min per IP (shared with /simulate) ─────────
    client_ip = http_request.client.host if http_request.client else 'unknown'
    now = time.time()
    _simulate_request_log.setdefault(client_ip, [])
    _simulate_request_log[client_ip] = [t for t in _simulate_request_log[client_ip] if now - t < 60]
    if len(_simulate_request_log[client_ip]) >= 10:
        raise HTTPException(status_code=429, detail='Rate limit exceeded. You can run 10 simulations per minute.')
    _simulate_request_log[client_ip].append(now)

    # ── LOAD INFRASTRUCTURE FROM DB ───────────────────────────────
    from app.database import SessionLocal, AnalysisLog

    infrastructure = None
    original_findings_data = None
    aws_account_id = None
    try:
        session = SessionLocal()
        try:
            logs = session.query(AnalysisLog).order_by(AnalysisLog.timestamp.desc()).limit(100).all()
            for log in logs:
                try:
                    data = json.loads(log.findings_json)
                    if data.get('analysis_id') == request.analysis_id:
                        infra_dict = data.get('infrastructure', {})
                        infrastructure = AWSInfrastructure(**infra_dict)
                        original_findings_data = data
                        aws_account_id = log.aws_account_id or None
                        break
                except Exception:
                    continue
        finally:
            session.close()
    except Exception as e:
        logger.error(f"simulate_component: DB load failed: {e}")

    if not infrastructure:
        raise HTTPException(status_code=404, detail='Scan data not found for this analysis ID. Please run a new scan first.')

    # ── DAILY SIMULATION LIMIT: 10/day per AWS account ─────────────
    SIMULATION_DAILY_LIMIT = 10
    WHITELISTED_ACCOUNTS = set(filter(None, os.getenv('WHITELISTED_ACCOUNTS', '').split(',')))
    if aws_account_id and aws_account_id not in WHITELISTED_ACCOUNTS:
        sim_count = get_simulation_count_today(aws_account_id)
        if sim_count >= SIMULATION_DAILY_LIMIT:
            raise HTTPException(
                status_code=429,
                detail=f'Simulation limit reached. Your account has used {sim_count}/{SIMULATION_DAILY_LIMIT} simulations today. Resets at midnight UTC.'
            )

    # ── DEEP-COPY AND MUTATE ──────────────────────────────────────
    mutated_infra_dict = copy.deepcopy(infrastructure.model_dump())
    config = request.config
    component_type = config.component_type

    new_node_info = None
    new_edges_info = []

    # component_type → node.type mapping:
    #   'ec2_instance'    → 'ec2_instance'
    #   'rds_instance'    → 'rds_instance'
    #   's3_bucket'       → 's3_bucket'
    #   'lambda_function' → 'lambda_function'
    #   'load_balancer'   → 'load_balancer'
    #   'api_gateway'     → 'api_gateway'
    #   'elasticache'     → 'elasticache'
    #   'ecs_service'     → 'ecs_tasks'
    #   'sg_rule'         → modifies existing security_group, no new node
    #   'iam_policy'      → modifies existing iam_role, no new node

    if component_type == 'ec2_instance':
        new_id = f"new-ec2-{uuid.uuid4().hex[:6]}"
        mutated_infra_dict['ec2']['instances'].append({
            'id': new_id,
            'type': config.instance_type,
            'sg_ids': config.sg_ids,
            'subnet_id': config.subnet_id or None,
            'state': 'running',
            'imdsv2_required': config.imdsv2_required,
        })
        mutated_infra_dict['ec2']['instance_count'] += 1
        mutated_infra_dict['ec2']['instance_ids'].append(new_id)
        if config.public_ip:
            mutated_infra_dict['ec2']['open_security_groups'] = list(
                set(mutated_infra_dict['ec2'].get('open_security_groups', []) + config.sg_ids)
            )
        new_node_info = {'id': new_id, 'type': 'ec2_instance', 'label': new_id}
        for sg_id in config.sg_ids:
            new_edges_info.append({'from': new_id, 'to': sg_id, 'relationship': 'uses_security_group'})
        if config.subnet_id:
            new_edges_info.append({'from': new_id, 'to': config.subnet_id, 'relationship': 'in_subnet'})

    elif component_type == 'rds_instance':
        new_id = f"new-rds-{uuid.uuid4().hex[:6]}"
        mutated_infra_dict['rds']['rds_instances'].append({
            'id': new_id,
            'sg_ids': config.sg_ids,
            'publicly_accessible': config.publicly_accessible,
            'encrypted': config.encrypted,
        })
        mutated_infra_dict['rds']['instances'].append(new_id)
        if config.publicly_accessible:
            mutated_infra_dict['rds']['publicly_accessible'].append(new_id)
        if not config.encrypted:
            mutated_infra_dict['rds']['unencrypted_instances'].append(new_id)
        if not config.deletion_protection:
            mutated_infra_dict['rds']['instances_without_deletion_protection'].append(new_id)
        if not config.multi_az:
            mutated_infra_dict['rds']['multi_az_enabled'] = False
        new_node_info = {'id': new_id, 'type': 'rds_instance', 'label': new_id}
        for sg_id in config.sg_ids:
            new_edges_info.append({'from': new_id, 'to': sg_id, 'relationship': 'uses_security_group'})
        if config.subnet_id:
            new_edges_info.append({'from': new_id, 'to': config.subnet_id, 'relationship': 'in_subnet'})

    elif component_type == 's3_bucket':
        new_id = f"new-s3-{uuid.uuid4().hex[:6]}"
        mutated_infra_dict['s3']['buckets'].append({
            'name': new_id,
            'is_public': config.is_public,
            'has_cloudfront': config.has_cloudfront,
            'policy': None,
            'is_empty': True,
        })
        mutated_infra_dict['s3']['total_buckets'] += 1
        if config.is_public:
            mutated_infra_dict['s3']['public_buckets'].append(new_id)
        if not config.encrypted:
            mutated_infra_dict['s3']['unencrypted_buckets'].append(new_id)
        if not config.versioning:
            mutated_infra_dict['s3']['buckets_without_versioning'].append(new_id)
        new_node_info = {'id': new_id, 'type': 's3_bucket', 'label': new_id}

    elif component_type == 'lambda_function':
        new_id = f"new-lambda-{uuid.uuid4().hex[:6]}"
        role_arn = f"arn:aws:iam::000000000000:role/{'admin-role' if config.role_type == 'admin' else 'least-priv-role'}"
        mutated_infra_dict['lambda_data']['functions'].append({
            'name': new_id,
            'role_arn': role_arn,
            'vpc_id': None,
            'subnet_ids': config.subnet_ids if config.in_vpc else [],
            'secret_refs': [],
        })
        mutated_infra_dict['lambda_data']['function_count'] += 1
        if config.role_type == 'admin':
            mutated_infra_dict['lambda_data']['functions_with_admin_role'].append(new_id)
        if config.timeout >= 900 or config.timeout <= 3:
            mutated_infra_dict['lambda_data']['functions_with_no_timeout'].append(new_id)
        new_node_info = {'id': new_id, 'type': 'lambda_function', 'label': new_id}
        if config.in_vpc and config.subnet_ids:
            for sid in config.subnet_ids:
                new_edges_info.append({'from': new_id, 'to': sid, 'relationship': 'in_subnet'})

    elif component_type == 'load_balancer':
        new_id = f"new-alb-{uuid.uuid4().hex[:6]}"
        new_arn = f"arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/{new_id}/0000"
        mutated_infra_dict['ec2']['load_balancers'].append({
            'arn': new_arn,
            'type': config.lb_type.lower(),
            'target_instances': config.target_instance_ids,
        })
        mutated_infra_dict['ec2']['has_load_balancer'] = True
        if not config.waf_attached:
            mutated_infra_dict['waf']['albs_without_waf'].append(new_arn)
        mutated_infra_dict['waf']['total_albs'] += 1
        new_node_info = {'id': new_arn, 'type': 'load_balancer', 'label': new_id}
        for inst_id in config.target_instance_ids:
            new_edges_info.append({'from': new_arn, 'to': inst_id, 'relationship': 'targets_instance'})

    elif component_type == 'api_gateway':
        new_id = f"new-apigw-{uuid.uuid4().hex[:6]}"
        new_node_info = {'id': new_id, 'type': 'api_gateway', 'label': new_id}
        # API Gateway doesn't map to existing infra models directly — graph-only node

    elif component_type == 'elasticache':
        new_id = f"new-cache-{uuid.uuid4().hex[:6]}"
        new_node_info = {'id': new_id, 'type': 'elasticache', 'label': new_id}
        # ElastiCache doesn't map to existing infra models directly — graph-only node

    elif component_type == 'ecs_service':
        new_id = f"new-ecs-{uuid.uuid4().hex[:6]}"
        mutated_infra_dict['ecs']['total_task_definitions'] += 1
        if config.privileged:
            mutated_infra_dict['ecs']['tasks_with_privileged_containers'].append(new_id)
        if not config.resource_limits:
            mutated_infra_dict['ecs']['tasks_without_resource_limits'].append(new_id)
        new_node_info = {'id': new_id, 'type': 'ecs_tasks', 'label': new_id}

    elif component_type == 'sg_rule':
        # Modify existing security group — no new node
        for sg in mutated_infra_dict['ec2']['security_groups']:
            if sg['id'] == config.sg_id:
                if config.action == 'add':
                    sg['rules'].append({
                        'port': config.port,
                        'protocol': config.protocol,
                        'ip_ranges': [config.source],
                        'direction': 'inbound',
                    })
                elif config.action == 'remove':
                    sg['rules'] = [
                        r for r in sg['rules']
                        if not (r.get('port') == config.port and config.source in r.get('ip_ranges', []))
                    ]
                break

    elif component_type == 'iam_policy':
        # Modify existing IAM role — no new node
        if config.action == 'attach' and 'Admin' in config.policy_name:
            mutated_infra_dict['iam']['users_with_admin_policy'].append(config.role_name)
        elif config.action == 'detach' and config.role_name in mutated_infra_dict['iam'].get('users_with_admin_policy', []):
            mutated_infra_dict['iam']['users_with_admin_policy'].remove(config.role_name)

    # ── REBUILD GRAPH + RUN CHECKS ────────────────────────────────
    mutated_infra = AWSInfrastructure(**mutated_infra_dict)
    mutated_graph = build_graph(mutated_infra)
    mutated_bfs = bfs_from_internet(mutated_graph)

    # Run all checks on mutated infrastructure (pure — no DB writes)
    mutated_findings = run_all_checks(mutated_infra, mutated_graph)
    mutated_combos = find_toxic_combos(
        mutated_findings,
        mutated_graph,
        mutated_infra
    )

    # ── DIFF FINDINGS ─────────────────────────────────────────────
    def finding_key(f):
        rid = f.get('rule_id', '') or (f.rule_id if hasattr(f, 'rule_id') else '')
        res = f.get('resource_id', '') or (f.resource_id if hasattr(f, 'resource_id') else '')
        return (rid, res)

    original_keys = set()
    for category in ['critical_risks', 'moderate_risks', 'low_risks', 'best_practices', 'cost_findings']:
        for f in original_findings_data.get(category, []):
            original_keys.add(finding_key(f))

    new_findings = []
    for category in ['critical_risks', 'moderate_risks', 'low_risks', 'best_practices', 'cost_findings']:
        for f in mutated_findings.get(category, []):
            f_dict = f.model_dump() if hasattr(f, 'model_dump') else f
            if finding_key(f_dict) not in original_keys:
                new_findings.append(f_dict)

    # Diff toxic combos
    original_combo_ids = {c.get('combo_id', '') for c in original_findings_data.get('toxic_combinations', [])}
    new_combos = [c.model_dump() if hasattr(c, 'model_dump') else c for c in mutated_combos if (c.get('combo_id') if isinstance(c, dict) else c.combo_id) not in original_combo_ids]

    # ── CALCULATE RISK DELTA ──────────────────────────────────────
    original_score = original_findings_data.get('overall_risk_score', 0)
    total_resources = original_findings_data.get('total_resources_scanned', 1) + (1 if new_node_info else 0)
    mutated_scores = calculate_score(mutated_findings, total_resources, mutated_infra)
    mutated_score = mutated_scores.get('overall_risk_score', 0)
    risk_delta = {
        'before_score': original_score,
        'after_score': mutated_score,
        'delta': mutated_score - original_score,
    }

    # ── ATTACK PATHS FOR NEW NODE ─────────────────────────────────
    attack_paths = []
    if new_node_info:
        # Check if new node is in BFS reachable set
        bfs_layers = mutated_bfs.get('layers', {})
        if new_node_info['id'] in bfs_layers:
            # Build path from INTERNET to new node
            path = ['INTERNET']
            # Simple: use BFS layers to reconstruct
            target_depth = bfs_layers[new_node_info['id']]
            if target_depth > 0:
                path.append(new_node_info['id'])
                attack_paths.append({'path': path, 'depth': target_depth})

    # ── CLAUDE NARRATIVE (Haiku — fast) ───────────────────────────
    narrative = {'verdict': '', 'severity': 'low', 'summary': '', 'recommendations': []}
    try:
        anthropic_client = anthropic_lib.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'), timeout=30)

        findings_summary = f"{len(new_findings)} new findings"
        if new_findings:
            severities = [f.get('severity', 'low') for f in new_findings]
            if 'Critical' in severities:
                findings_summary = f"{len(new_findings)} new findings ({severities.count('Critical')} critical)"

        # Pre-interpret the delta so Claude doesn't have to figure out scoring direction
        if risk_delta['delta'] > 0:
            score_interpretation = f"Score IMPROVED from {original_score} to {mutated_score} (+{risk_delta['delta']} points safer). This is GOOD — the component made the infrastructure more secure."
        elif risk_delta['delta'] < 0:
            score_interpretation = f"Score WORSENED from {original_score} to {mutated_score} ({risk_delta['delta']} points riskier). This is BAD — the component introduced risk."
        else:
            score_interpretation = f"Score unchanged at {original_score}. The component has neutral impact."

        narrative_prompt = f"""You are analyzing the impact of adding a new component to AWS infrastructure.

Component: {component_type}
Configuration: {json.dumps(config.model_dump(), indent=2)}

Impact:
- New findings: {findings_summary}
- Score impact: {score_interpretation}
- New toxic combinations: {len(new_combos)}
- Internet reachable: {'Yes' if new_node_info and new_node_info['id'] in mutated_bfs.get('layers', {}) else 'No'}

CRITICAL RULE: If the score IMPROVED and there are 0 new findings, the component is SAFE. Say it is safe to deploy. Do NOT say it introduces risk or security gaps.

New findings details:
{json.dumps(new_findings[:5], indent=2, default=str)}

Respond with ONLY this JSON (no markdown):
{{"verdict": "one sentence direct verdict about the impact", "severity": "low|medium|high|critical", "summary": "2-3 sentences explaining the risk", "recommendations": [{{"title": "short fix title", "explanation": "one sentence how to fix"}}]}}"""

        msg = anthropic_client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=300,
            cache_control={"type": "ephemeral"},
            messages=[{"role": "user", "content": narrative_prompt}]
        )
        raw = msg.content[0].text.strip().replace('```json', '').replace('```', '').strip()
        narrative = json.loads(raw)
    except Exception as e:
        logger.warning(f"simulate_component: Claude narrative failed (non-fatal): {e}")
        # Fallback: generate narrative from facts
        if new_findings:
            max_sev = 'critical' if any(f.get('severity') == 'Critical' for f in new_findings) else 'medium'
            narrative = {
                'verdict': f'Adding this {component_type.replace("_", " ")} introduces {len(new_findings)} new security finding(s).',
                'severity': max_sev,
                'summary': f'The new component creates {len(new_findings)} finding(s) and {len(new_combos)} toxic combination(s). Risk score changes from {original_score} to {mutated_score}.',
                'recommendations': [{'title': f.get('recommendation', 'Review finding'), 'explanation': f.get('issue', '')} for f in new_findings[:3]],
            }
        else:
            narrative = {
                'verdict': f'This {component_type.replace("_", " ")} is safe to deploy. No new risks introduced.',
                'severity': 'low',
                'summary': 'No new security findings or toxic combinations detected.',
                'recommendations': [],
            }

    # ── LOG SIMULATION FOR DAILY LIMIT TRACKING ───────────────────
    if aws_account_id:
        try:
            save_simulation_log(aws_account_id, request.analysis_id, f"[add_component] {component_type}")
        except Exception as sim_log_err:
            logger.warning(f"simulate_component: failed to save simulation log: {sim_log_err}")

    # ── RETURN RESPONSE ───────────────────────────────────────────
    return {
        'new_node': new_node_info,
        'new_edges': new_edges_info,
        'new_findings': new_findings,
        'new_toxic_combos': new_combos,
        'attack_paths': attack_paths,
        'narrative': narrative,
        'risk_delta': risk_delta,
    }


# ── PRIVACY: PURGE USER DATA ──────────────────────────────────────
# Lets a user delete every row + S3 object tied to their AWS account.
# Re-assumes the role to prove the caller controls the account before deleting.

from pydantic import BaseModel as _PurgeBase

class PurgeRequest(_PurgeBase):
    role_arn: str
    region: str = 'us-east-1'

@app.post('/privacy/purge')
def purge_user_data(payload: PurgeRequest, request: Request):
    """
    Delete all stored data for the AWS account that owns this role.
    Re-assumes the role to verify caller controls the account.
    Deletes from analysis_logs, drift_events, simulation_logs + S3 reports.
    """
    import re as _re
    # Validate role ARN format and extract account ID
    match = _re.match(r'^arn:aws:iam::(\d{12}):role/[\w+=,.@\-/]+$', payload.role_arn or '')
    if not match:
        raise HTTPException(status_code=400, detail='Invalid role ARN format')
    account_id = match.group(1)

    # Re-assume the role: caller must control this AWS account.
    # If they can't assume, they can't purge.
    try:
        sts = boto3.client('sts')
        sts.assume_role(
            RoleArn=payload.role_arn,
            RoleSessionName='emfirge-purge',
            ExternalId='aws-risk-agent',
            DurationSeconds=900,
        )
    except ClientError as e:
        code = e.response.get('Error', {}).get('Code', 'Unknown')
        raise HTTPException(status_code=403, detail=f'Cannot assume role ({code}). Stack may be missing or trust policy wrong.')
    except Exception as e:
        raise HTTPException(status_code=403, detail=f'Role verification failed: {str(e)[:200]}')

    # Collect analysis UUIDs first (needed for S3 cleanup), then delete DB rows
    from app.database import SessionLocal, AnalysisLog, DriftEvent, SimulationLog
    deleted_counts = {'analysis_logs': 0, 'drift_events': 0, 'simulation_logs': 0, 's3_objects': 0}
    analysis_uuids = []
    session = SessionLocal()
    try:
        rows = session.query(AnalysisLog).filter_by(aws_account_id=account_id).all()
        for row in rows:
            try:
                data = json.loads(row.findings_json) if row.findings_json else {}
                uid = data.get('analysis_id')
                if uid:
                    analysis_uuids.append(uid)
            except Exception:
                pass

        deleted_counts['analysis_logs'] = session.query(AnalysisLog).filter_by(aws_account_id=account_id).delete()
        deleted_counts['drift_events'] = session.query(DriftEvent).filter_by(aws_account_id=account_id).delete()
        deleted_counts['simulation_logs'] = session.query(SimulationLog).filter_by(aws_account_id=account_id).delete()
        session.commit()
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f'DB purge failed: {str(e)[:200]}')
    finally:
        session.close()

    # S3 cleanup. Best-effort: errors are logged, not raised.
    try:
        bucket = os.getenv('S3_BUCKET_NAME')
        if bucket and analysis_uuids:
            s3 = boto3.client(
                's3',
                aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
                region_name=os.getenv('AWS_REGION', 'ap-south-1'),
            )
            uid_set = set(analysis_uuids)
            for prefix in ('reports/', 'snapshots/'):
                token = None
                while True:
                    kwargs = {'Bucket': bucket, 'Prefix': prefix}
                    if token:
                        kwargs['ContinuationToken'] = token
                    resp = s3.list_objects_v2(**kwargs)
                    for obj in resp.get('Contents', []):
                        key = obj['Key']
                        if any(uid in key for uid in uid_set):
                            try:
                                s3.delete_object(Bucket=bucket, Key=key)
                                deleted_counts['s3_objects'] += 1
                            except Exception as del_err:
                                logger.warning(f'S3 delete failed for {key}: {del_err}')
                    if not resp.get('IsTruncated'):
                        break
                    token = resp.get('NextContinuationToken')
    except Exception as e:
        logger.warning(f'S3 purge step failed: {e}')

    return {
        'status': 'purged',
        'aws_account_id': account_id,
        'deleted': deleted_counts,
    }
