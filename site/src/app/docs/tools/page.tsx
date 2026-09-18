import { DocHeader, Lead, H2, P, Strong, Code, Callout, PrevNext } from "@/components/docs/ui";
import { prevNext } from "@/lib/nav";
import Link from "next/link";

export const metadata = { title: "MCP Tools · Emfirge Docs", description: "The 15 tools Emfirge exposes to your AI, grouped by analysis, branch modeling, and setup." };

const GROUPS = [
  { title: "Analyze", tools: [
    ["emfirge_scan", "/docs/tools/scan", "Scan an AWS account for security risks; returns score, counts, and analysis_id."],
    ["emfirge_get_findings", "/docs/tools/get-findings", "Get the full findings list for a previous scan, optionally filtered by severity."],
    ["emfirge_attack_paths", "/docs/tools/attack-paths", "Get internet-to-resource attack paths, chokepoints, and orphaned resources."],
    ["emfirge_simulate_breach", "/docs/tools/simulate-breach", "Walk a natural-language what-if through entry, pivot, impact, and blast radius."],
    ["emfirge_verify_fix", "/docs/tools/verify-fix", "Simulate a finding fix on a clone and return score and finding deltas."],
    ["emfirge_check_compliance", "/docs/tools/check-compliance", "Get CIS AWS Foundations 1.5 or SOC 2 per-control status."],
  ]},
  { title: "Branch", tools: [
    ["emfirge_create_branch", "/docs/tools/create-branch", "Create an isolated infrastructure branch from a completed analysis."],
    ["emfirge_apply_change", "/docs/tools/apply-change", "Apply an add, modify, or delete change to the branch model, not AWS."],
    ["emfirge_branch_diff", "/docs/tools/branch-diff", "Show the infrastructure diff against the branch base analysis."],
    ["emfirge_branch_verdict", "/docs/tools/branch-verdict", "Evaluate the advisory security verdict for modeled branch changes."],
    ["emfirge_rollback_branch", "/docs/tools/rollback-branch", "Remove the most recent modeled branch change."],
    ["emfirge_discard_branch", "/docs/tools/discard-branch", "Discard an isolated branch when it is no longer needed."],
    ["emfirge_list_branches", "/docs/tools/list-branches", "List branches, optionally filtered by base analysis ID."],
    ["emfirge_compare_branches", "/docs/tools/compare-branches", "Compare branch models and rank their modeled outcomes safest-first."],
  ]},
  { title: "Setup", tools: [["emfirge_setup_help", "/docs/tools/setup-help", "Return the CloudFormation deploy URL for a read-only IAM role."]] },
] as const;

export default function Page() {
  const { prev, next } = prevNext("/docs/tools");
  return <><DocHeader eyebrow="MCP Tools" title="Overview"><Lead>Emfirge exposes <Strong>15 tools</Strong> over the Model Context Protocol. They are grouped into analysis, isolated branch modeling, and setup. Branch operations model changes and do not mutate AWS.</Lead></DocHeader>
    {GROUPS.map((group) => <section key={group.title}><H2>{group.title}</H2><div className="mt-6 overflow-hidden rounded-xl border border-border">{group.tools.map(([name, href, desc], i) => <Link key={name} href={href} className={`block px-4 py-4 transition-colors hover:bg-accent/50 ${i !== 0 ? "border-t border-border-soft" : ""}`}><code className="font-mono text-[13.5px] font-medium text-foreground">{name}</code><p className="mt-1.5 text-[13.5px] leading-relaxed text-muted-foreground">{desc}</p></Link>)}</div></section>)}
    <H2>The typical flow</H2><P>Most sessions start with <Code>emfirge_scan</Code>, which returns an <Code>analysis_id</Code>. Analyze tools use that snapshot. Branch tools fork it, apply modeled changes, then expose diff, verdict, rollback, listing, and comparison operations.</P><Callout type="note" title="Advisory results">The engine computes evidence and security deltas from the scanned snapshot and modeled branch. It does not guarantee safe deployment or application connectivity.</Callout><PrevNext prev={prev} next={next} /></>;
}
