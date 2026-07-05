from google import genai
import os
import json
import time
from typing import Optional

PROMPT_VERSION = 'v3.1'

def _call_gemini(client, prompt: str, timeout: int = 15) -> dict:
    """Private helper that calls Gemini and returns parsed result. Raises exception on any failure."""
    import signal
    import threading

    start = time.time()

    # Use a thread with timeout to prevent Gemini from hanging
    result_container = [None]
    error_container = [None]

    def _call():
        try:
            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt
            )
            result_container[0] = response
        except Exception as e:
            error_container[0] = e

    thread = threading.Thread(target=_call)
    thread.start()
    thread.join(timeout=timeout)

    if thread.is_alive():
        raise TimeoutError(f"Gemini call exceeded {timeout}s timeout")

    if error_container[0]:
        raise error_container[0]

    response = result_container[0]
    latency = int((time.time() - start) * 1000)

    # Clean the response and parse it as JSON
    text = response.text.strip()
    text = text.replace('```json', '').replace('```', '').strip()
    result = json.loads(text)

    # Validate priority_actions structure — if Gemini returns malformed data,
    # we catch it here and fall back gracefully instead of crashing the scan
    raw_actions = result.get('priority_actions', [])
    priority_actions = []
    for action in raw_actions:
        if all(k in action for k in ['rank', 'title', 'what_is_wrong', 'why_dangerous', 'fix_steps']):
            priority_actions.append(action)

    return {
        'ai_summary': result.get('ai_summary', 'Analysis complete.'),
        'priority_actions': priority_actions,
        'latency_ms': latency
    }

def generate_explanation(findings_dict: dict, risk_score: int, region: str) -> dict:
    # Get Gemini API key from .env file
    api_key = os.getenv('GEMINI_API_KEY')

    # Early check — if no API key, skip client creation entirely
    client = None
    if api_key:
        try:
            client = genai.Client(api_key=api_key)
        except Exception:
            client = None

    # Only send critical and moderate risks to Gemini
    # Best practices are removed — Gemini should focus on what's broken, not what's good
    critical = findings_dict.get('critical_risks', [])
    moderate = findings_dict.get('moderate_risks', [])

    # Cap total findings sent to Gemini at 5 — criticals always take priority
    critical = critical[:5]
    moderate = moderate[:max(0, 5 - len(critical))]

    # Build rich structured context per finding so Gemini can give specific,
    # resource-aware advice instead of generic recommendations
    # Each finding includes: issue, resource ID, region, category, attack path, and blast radius
    def format_findings(findings) -> str:
        if not findings:
            return 'None'
        lines = []
        for f in findings:
            resource = f.resource_id if f.resource_id else 'N/A'
            lines.append(
                f"- Issue: {f.issue}\n"
                f"  Resource: {resource}\n"
                f"  Region: {f.region or region}\n"
                f"  Category: {f.category}\n"
                f"  Attack Path: {' -> '.join(f.attack_path) if f.attack_path else 'N/A'}\n"
                f"  Blast Radius: {f.blast_radius} resources exposed"
            )
        return '\n'.join(lines)

    critical_text = format_findings(critical)
    moderate_text = format_findings(moderate)

    # Total findings count — used to cap priority_actions at 3
    total_findings = len(critical) + len(moderate)

    # How many priority actions to generate — max 3, min 1
    action_count = min(total_findings, 3)

    # ── ADVISOR PROMPT v3.1 ───────────────────────────────────────
    # Key changes from v3.0:
    # - Dropped recommended_improvements from Gemini (auto-generated from findings now)
    # - Capped priority_actions at 3 (matches what dashboard shows)
    # - Smaller prompt = faster response + less cost
    prompt = f"""
You are an AWS security advisor helping a solo developer or small team understand and fix real security risks in their AWS account.

Your job is NOT to write a formal report. Your job is to act like a knowledgeable friend who looked at their AWS account and is telling them exactly what's wrong, why it's dangerous, and precisely how to fix it — in plain English.

Account details:
- Region: {region}
- Overall risk score: {risk_score}/100 (higher = safer)

Critical risks found:
{critical_text}

Moderate risks found:
{moderate_text}

Your response must be valid JSON in this exact format — no extra text, no markdown, no code fences:

{{
    "ai_summary": "2-3 sentence plain English summary of the most important risks and what they mean for this specific account. Mention the region and risk score. Do not use jargon.",
    "priority_actions": [
        {{
            "rank": "01",
            "title": "Short title of the single most important thing to fix (max 8 words)",
            "what_is_wrong": "One sentence explaining the problem in plain English. Mention the specific resource ID if available.",
            "why_dangerous": "One or two sentences describing the exact real-world attack scenario. What does an attacker actually do with this? What happens to the account or data? Be specific and concrete — no vague phrases like 'could lead to unauthorized access'.",
            "fix_steps": [
                "Step 1: Go to [exact AWS console location]",
                "Step 2: [exact action to take]",
                "Step 3: [exact action to take]"
            ]
        }}
    ]
}}

Rules for priority_actions:
- Include exactly {action_count} items (one per finding, max 3)
- Rank 01 = highest priority (biggest impact, easiest to fix)
- Rank the rest by impact × ease — quick wins that eliminate serious risk go first
- For each finding, use the attack_path to describe exactly how an attacker moves from entry point to sensitive resource. Use blast_radius to communicate real impact — how many resources are at risk if this finding is exploited.
- why_dangerous must describe a real attacker scenario. Example: "Automated scanners probe port 22 every minute across the internet. Once found, they run credential stuffing attacks. If your SSH key is weak or reused, the server is compromised within hours."
- fix_steps must be exact AWS console steps. Example: "Step 1: Go to EC2 > Security Groups in the AWS Console. Step 2: Select security group sg-0a1b2c3. Step 3: Edit inbound rules. Step 4: Delete the rule allowing port 22 from 0.0.0.0/0. Step 5: Add a new rule for port 22 restricted to your IP address only."
- Never use phrases like "consider", "you may want to", "it is recommended". Be direct.
- Write like you are talking to a smart developer who is not an AWS expert yet.

Context-aware fix rules you MUST follow:
- SSH/port 22 open on EC2: NEVER suggest closing SSH entirely. Always suggest restricting to specific IP only. Closing SSH locks the owner out of their server.
- Port 80/443 open: This is intentional for web servers. Only flag if unexpected ports are open.
- IAM user with no console access: MFA finding is LOW not CRITICAL. MFA only matters for users who log into AWS Console.
- Resource name contains dev/test/staging: Note it may be intentional and ask user to verify before fixing.
- Never give steps that could take down a running application.
"""

    # ── AUTO-GENERATE recommended_improvements FROM FINDINGS ─────
    # These are generated from the findings themselves — no AI needed.
    # Maps each finding's aws_service to a concrete one-liner action.
    _service_to_quick_win = {
        'IAM': 'Enable MFA on all IAM users and remove unused access keys',
        'EC2': 'Restrict open security group ports to specific IP addresses only',
        'S3': 'Block all public access on S3 buckets that don\'t need it',
        'RDS': 'Move RDS instances to private subnets and enable encryption',
        'CloudTrail': 'Enable CloudTrail with multi-region logging',
        'Budgets': 'Set up AWS Budget alerts to catch surprise bills early',
        'CloudWatch': 'Create CloudWatch alarms for critical metrics',
        'GuardDuty': 'Enable GuardDuty for automated threat detection',
        'Lambda': 'Scope down Lambda execution roles to least privilege',
        'Secrets Manager': 'Enable automatic rotation on all secrets',
        'VPC': 'Enable VPC flow logs for network visibility',
        'KMS': 'Enable automatic key rotation on all CMKs',
        'Config': 'Enable AWS Config to track resource compliance',
        'SNS': 'Enable encryption on SNS topics',
        'ECS': 'Remove privileged mode from ECS task definitions',
        'WAF': 'Attach WAF to all public-facing ALBs',
    }

    all_findings_for_recs = critical + moderate
    seen_services = set()
    auto_recommendations = []
    for f in all_findings_for_recs:
        svc = f.aws_service
        if svc not in seen_services and svc in _service_to_quick_win:
            seen_services.add(svc)
            auto_recommendations.append(_service_to_quick_win[svc])
        if len(auto_recommendations) >= 5:
            break
    # Pad with generic best practices if we have fewer than 5
    _generic_recs = [
        'Review and fix all critical risks immediately',
        'Enable MFA on all IAM users',
        'Enable CloudTrail for audit logging',
        'Set up AWS Budget alerts to avoid surprise bills',
        'Review security group rules monthly',
    ]
    for rec in _generic_recs:
        if rec not in auto_recommendations and len(auto_recommendations) < 5:
            auto_recommendations.append(rec)

    try:
        if not client:
            raise ValueError("No Gemini client available")
        result = _call_gemini(client, prompt, timeout=12)
        if result['priority_actions']:
            result['recommended_improvements'] = auto_recommendations
            return result
        # Empty priority_actions — use fallback immediately
    except Exception as e:
        print(f'Gemini failed: {e}')
        # Fall through to fallback
    
    # Fallback: Build priority_actions from critical and moderate findings
    print('Gemini failed or returned empty priority_actions, using fallback')
    
    # Category-specific why_dangerous messages
    category_dangers = {
        'IAM': "An attacker with IAM access can create backdoor users, escalate privileges, and lock you out of your own account.",
        'S3': "A public S3 bucket can be discovered by automated scanners in minutes, exposing all stored files to anyone on the internet.",
        'EC2': "Open ports are probed by automated bots constantly. A single weak credential means full server compromise.",
        'RDS': "A publicly accessible database exposes all your application data directly to the internet without any application-layer protection.",
        'CloudTrail': "Without CloudTrail, an attacker can operate inside your account for weeks with no audit trail to detect or investigate them.",
        'Cost': "Without budget alerts, an attacker who gains access can spin up expensive resources and cause thousands in charges before you notice.",
        'GuardDuty': "Without GuardDuty, active threats like compromised credentials or crypto mining go completely undetected.",
        'Lambda': "Overprivileged Lambda functions give attackers a serverless pivot point to access other AWS services if the function is compromised.",
        'Secrets Manager': "Unrotated secrets that leak via logs or code repos remain valid indefinitely, giving attackers persistent access.",
        'VPC': "Without VPC flow logs, network-level attacks and data exfiltration are completely invisible."
    }
    
    # Combine critical and moderate findings (critical first)
    all_findings = critical + moderate
    fallback_actions = []
    
    for i, f in enumerate(all_findings[:3]):  # Max 3 items (matches dashboard)
        rank = f"{i+1:02d}"  # Zero-padded: 01, 02, 03, 04, 05
        
        # Build what_is_wrong with resource_id if available
        what_is_wrong = f.issue
        if f.resource_id:
            what_is_wrong += f" — Resource: {f.resource_id}"
        
        # Get category-specific danger message
        why_dangerous = category_dangers.get(f.aws_service, 
            "This misconfiguration could expose your AWS account to unauthorized access or data loss.")
        
        fallback_actions.append({
            'rank': rank,
            'title': f.issue,
            'what_is_wrong': what_is_wrong,
            'why_dangerous': why_dangerous,
            'fix_steps': [f.recommendation]
        })
    
    # Fallback ai_summary
    top_issues = [f.issue for f in all_findings[:3]]
    fallback_summary = f"Your account scored {risk_score}/100 in {region}. We found {len(critical)} critical and {len(moderate)} moderate risks. Top issues: {', '.join(top_issues)}."
    
    return {
        'ai_summary': fallback_summary,
        'recommended_improvements': auto_recommendations,
        'priority_actions': fallback_actions,
        'latency_ms': 0
    }