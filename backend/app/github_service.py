import os
import base64
from typing import Optional
from github import Github, GithubIntegration

def _get_private_key() -> str:
    key_b64 = os.getenv('GITHUB_PRIVATE_KEY_B64', '')
    return base64.b64decode(key_b64).decode('utf-8')

def get_github_client(installation_id: int) -> Github:
    private_key = _get_private_key()
    app_id = int(os.getenv('GITHUB_APP_ID', '0'))
    integration = GithubIntegration(app_id, private_key)
    token = integration.get_access_token(installation_id).token
    return Github(token)

def search_tf_files(gh: Github, repo_full_name: str, resource_id: str, resource_type: str) -> list:
    results = []
    try:
        found = gh.search_code(f"repo:{repo_full_name} {resource_id} extension:tf")
        results = [f.path for f in found][:3]
    except Exception:
        pass
    if not results and resource_type:
        try:
            found = gh.search_code(f"repo:{repo_full_name} {resource_type} extension:tf")
            results = [f.path for f in found][:3]
        except Exception:
            pass
    return results


def create_fix_pr(
    gh: Github,
    repo_full_name: str,
    finding: dict,
    hcl: str,
    file_path: str = None,
    tf_match: Optional[dict] = None,
) -> dict:
    """
    Create a fix PR. If tf_match is provided (from TF index), creates a surgical
    diff on the exact file/block. Otherwise falls back to standalone HCL file.

    tf_match shape: {file_path, block_content, resource_type, resource_name, line_number}
    """
    repo = gh.get_repo(repo_full_name)
    rule_id = (finding.get('rule_id') or 'fix').lower().replace('_', '-')
    resource_id = (finding.get('resource_id') or 'resource')[:8]
    branch_name = f"emfirge/fix-{rule_id}-{resource_id}"

    base = repo.get_branch(repo.default_branch)

    # Check if branch already exists — return existing PR if so
    try:
        repo.get_branch(branch_name)
        # Branch exists — find open PR
        open_prs = list(repo.get_pulls(state='open', head=f'{repo.owner.login}:{branch_name}'))
        if open_prs:
            pr = open_prs[0]
            return {"pr_url": pr.html_url, "pr_number": pr.number, "branch": branch_name}
        # Branch exists but PR was closed/merged — append timestamp to branch name
        import time
        branch_name = f"{branch_name}-{int(time.time())}"
    except Exception:
        pass  # Branch doesn't exist, proceed normally

    repo.create_git_ref(f"refs/heads/{branch_name}", base.commit.sha)

    # Determine fix strategy
    if tf_match and tf_match.get('file_path'):
        # SURGICAL FIX: Modify the exact resource block in the user's TF file
        tf_file_path = tf_match['file_path']
        try:
            current = repo.get_contents(tf_file_path, ref=branch_name)
            original_content = current.decoded_content.decode('utf-8')

            # Replace the old block with the new HCL
            old_block = tf_match.get('block_content', '')
            if old_block and old_block in original_content:
                new_content = original_content.replace(old_block, hcl, 1)
            else:
                # Fallback: append fix as a comment + new block at end of file
                new_content = original_content + f"\n\n# EMFIRGE FIX: {finding['issue']}\n{hcl}"

            repo.update_file(
                tf_file_path,
                f"fix({finding.get('aws_service','aws')}): {finding['issue'][:50]}",
                new_content,
                current.sha,
                branch=branch_name
            )
            file_path = tf_file_path
        except Exception as e:
            print(f"[github_service] Surgical fix failed, falling back: {e}")
            # Fall back to standalone file
            file_path = f"emfirge-fixes/{rule_id}.tf"
            repo.create_file(
                file_path,
                f"fix({finding.get('aws_service','aws')}): {finding['issue'][:50]}",
                hcl,
                branch=branch_name
            )
    elif file_path:
        current = repo.get_contents(file_path, ref=branch_name)
        new_content = current.decoded_content.decode('utf-8') + f"\n\n# EMFIRGE FIX: {finding['issue']}\n{hcl}"
        repo.update_file(
            file_path,
            f"fix({finding.get('aws_service','aws')}): {finding['issue'][:50]}",
            new_content,
            current.sha,
            branch=branch_name
        )
    else:
        file_path = f"emfirge-fixes/{rule_id}.tf"
        repo.create_file(
            file_path,
            f"fix({finding.get('aws_service','aws')}): {finding['issue'][:50]}",
            hcl,
            branch=branch_name
        )

    attack_path = finding.get('attack_path') or []
    if attack_path:
        path_parts = ['🌐 Internet'] + attack_path
        attack_path_str = ' → '.join(path_parts)
    else:
        resource_id = finding.get('resource_id', '')
        attack_path_str = f'🌐 Internet → {resource_id}' if resource_id else '🌐 Internet'

    mitre_id = finding.get('mitre_technique_id')
    mitre_name = finding.get('mitre_technique_name')
    mitre_line = f"\n**MITRE ATT&CK:** [{mitre_id} — {mitre_name}](https://attack.mitre.org/techniques/{mitre_id.replace('.','/')})" if mitre_id else ""

    # Add context-aware badge if surgical fix was used
    fix_type_badge = ""
    if tf_match and tf_match.get('file_path'):
        fix_type_badge = "\n\n> ✅ **Context-aware fix** — this PR modifies your existing Terraform file directly."
    else:
        fix_type_badge = "\n\n> ℹ️ **Standalone fix** — Emfirge couldn't locate the resource in your repo. This creates a new file."

    pr_body = f"""## 🔒 Security Fix: {finding['issue']}

**Severity:** {finding.get('severity','').upper()} | **Service:** {finding.get('aws_service','')}
{fix_type_badge}

### What's wrong
{finding.get('issue','')}

### Why it's dangerous
{finding.get('recommendation','')}

**Attack path closed by this fix:**
`🌐 {attack_path_str}`{mitre_line}

### Before merging, verify:
- [ ] Review the terraform change matches your infrastructure
- [ ] Run `terraform plan` to confirm 0 destroys
- [ ] Test in staging before applying to production

---
*Opened automatically by [Emfirge](https://emfirge.cloud)*"""

    pr = repo.create_pull(
        title=f"🔒 [{finding.get('severity','').upper()}] {finding.get('issue','')}",
        body=pr_body,
        head=branch_name,
        base=repo.default_branch
    )
    return {"pr_url": pr.html_url, "pr_number": pr.number, "branch": branch_name}


def post_pr_comment(gh: Github, repo_full_name: str, pr_number: int, body: str) -> None:
    """Post or update an Emfirge comment on a PR."""
    repo = gh.get_repo(repo_full_name)
    pr = repo.get_pull(pr_number)

    # Find existing Emfirge comment to update (avoid spam)
    for comment in pr.get_issue_comments():
        if comment.body and 'Emfirge Security Gate' in comment.body:
            comment.edit(body)
            return

    pr.create_issue_comment(body)


def create_check_run(gh: Github, repo_full_name: str, head_sha: str, status: str, summary: str, details: str = "") -> None:
    """
    Create a GitHub Check Run for the commit.

    Args:
        gh: Authenticated GitHub client
        repo_full_name: e.g. "theanshsonkar/emfirge-test-infra"
        head_sha: The commit SHA to attach the check to
        status: "pass", "fail", "warn", or "skip"
        summary: One-line summary
        details: Full markdown body for the check details
    """
    repo = gh.get_repo(repo_full_name)

    conclusion = {
        "pass": "success",
        "fail": "failure",
        "warn": "neutral",
        "skip": "skipped",
    }.get(status, "neutral")

    repo.create_check_run(
        name="Emfirge Security",
        head_sha=head_sha,
        status="completed",
        conclusion=conclusion,
        output={
            "title": f"Emfirge: {summary[:60]}",
            "summary": summary,
            "text": details or summary,
        }
    )


def build_pr_comment_body(result: dict) -> str:
    """
    Build the markdown body for a PR comment from CI analysis results.

    Args:
        result: Dict with status, score_delta, new_findings, resolved_findings,
                new_toxic_combos, summary, scan_age_hours
    """
    status = result.get('status', 'skip')
    summary = result.get('summary', '')
    score_delta = result.get('score_delta', 0)
    new_findings = result.get('new_findings', [])
    resolved_findings = result.get('resolved_findings', [])
    new_toxic_combos = result.get('new_toxic_combos', [])
    scan_age_hours = result.get('scan_age_hours')

    badge = {
        'fail': '🚨 FAIL',
        'warn': '⚠️ WARN',
        'skip': '⏭️ SKIP',
        'pass': '✅ PASS',
    }.get(status, '✅ PASS')

    score_icon = '📉' if score_delta < 0 else '📈' if score_delta > 0 else '➡️'

    body = f"## Emfirge Security Gate — {badge}\n\n"
    body += f"{summary}\n\n"

    # Metrics table
    if status != 'skip':
        body += "| Metric | Value |\n|---|---|\n"
        body += f"| {score_icon} Score Impact | **{'+' if score_delta > 0 else ''}{score_delta}** points |\n"
        body += f"| 🔍 New Findings | {len(new_findings)} |\n"
        if resolved_findings:
            body += f"| ✅ Resolved | {len(resolved_findings)} |\n"
        if new_toxic_combos:
            body += f"| ☠️ Toxic Combos | {len(new_toxic_combos)} new |\n"
        if scan_age_hours and scan_age_hours != 'unknown':
            body += f"| 🕐 Scan Age | {int(float(scan_age_hours))}h ago |\n"
        body += "\n"

    # New findings details
    if new_findings:
        body += "### New Findings\n\n"
        for f in new_findings[:10]:
            sev = '🔴' if f.get('severity') == 'Critical' else '🟡' if f.get('severity') == 'Moderate' else '⚪'
            file_str = f" `{f['file_path']}`" if f.get('file_path') else ''
            path_str = ' ⚡ _internet-reachable_' if f.get('attack_path') else ''
            body += f"- {sev} **{f.get('severity')}** — {f.get('issue', '')}{file_str}{path_str}\n"
        if len(new_findings) > 10:
            body += f"\n_...and {len(new_findings) - 10} more_\n"
        body += "\n"

    # Resolved findings
    if resolved_findings:
        body += "### ✅ Resolved by This PR\n\n"
        for f in resolved_findings[:5]:
            body += f"- ~~{f.get('issue', f.get('rule_id', ''))}~~\n"
        body += "\n"

    # Footer
    body += "---\n"
    body += "<details><summary>How does this work?</summary>\n\n"
    body += "Emfirge simulates your Terraform changes against your **actual live AWS infrastructure**:\n\n"
    body += "1. Parses the PR diff for resource additions/modifications\n"
    body += "2. Deep-copies your last scan's infrastructure state\n"
    body += "3. Applies the PR changes to the copy\n"
    body += "4. Rebuilds the infrastructure graph\n"
    body += "5. Runs BFS from internet to detect new attack paths\n"
    body += "6. Executes all 58 security rules on the mutated state\n"
    body += "7. Diffs findings to show only what THIS PR introduces\n\n"
    body += "This is not a static lint — it's a live simulation.\n"
    body += "</details>\n\n"
    body += "*Powered by [Emfirge](https://emfirge.cloud)*"

    return body
