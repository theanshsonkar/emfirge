"""
Drift detection service.

Compares findings between consecutive scans to identify newly introduced
risks (regressions) and resolved issues (fixes). Used by the /drift/events
endpoint and the history trend calculations.
"""

from typing import List, Tuple


def compare_findings(current: list, previous: list) -> Tuple[List[dict], List[dict], List[dict]]:
    """
    Diff two scan results to find new, fixed, and severity-changed findings.

    Returns:
        (new_findings, fixed_findings, severity_changed) —
        new = appeared since last scan,
        fixed = present in previous but absent in current,
        severity_changed = same finding with different severity (e.g., graph-aware downgrade).
    """

    def key(f):
        return f"{f.get('rule_id', '')}::{f.get('resource_id', '')}"

    current_map = {key(f): f for f in current}
    previous_map = {key(f): f for f in previous}

    new_findings = [f for k, f in current_map.items() if k not in previous_map]
    fixed_findings = [f for k, f in previous_map.items() if k not in current_map]

    # Detect severity changes on same finding (e.g., graph-aware downgrade/upgrade)
    severity_changed = []
    for k in current_map:
        if k in previous_map:
            curr_sev = current_map[k].get('severity')
            prev_sev = previous_map[k].get('severity')
            if curr_sev != prev_sev:
                severity_changed.append({
                    **current_map[k],
                    'previous_severity': prev_sev,
                    'change_reason': 'graph_context'
                })

    return new_findings, fixed_findings, severity_changed
