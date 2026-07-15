import { A, DocHeader, Lead, H2, P, Strong, Code, Badge, ParamList, Param, Callout, PrevNext, ToolSignature } from "@/components/docs/ui";
import { CodeBlock } from "@/components/docs/code-block";
import { EyeOff } from "lucide-react";
import { prevNext } from "@/lib/nav";

export const metadata = {
  title: "emfirge_attack_paths · Emfirge Docs",
  description: "Attack paths from the internet to internal resources, plus chokepoints and orphaned resources.",
};

export default function Page() {
  const { prev, next } = prevNext("/docs/tools/attack-paths");
  return (
    <>
      <DocHeader eyebrow="MCP Tools" title="emfirge_attack_paths" mono>
        <Lead>
          Get the routes an attacker could take from the internet to your internal resources, ranked
          by exploit difficulty, plus the <Strong>chokepoints</Strong> that sever the most paths and
          any <Strong>orphaned</Strong> resources.
        </Lead>
        <div className="mt-5 flex flex-wrap gap-2">
          <Badge><EyeOff className="size-3.5" /> read-only</Badge>
          <Badge>graph analysis</Badge>
        </div>
      </DocHeader>

      <ToolSignature name="emfirge_attack_paths" args="analysis_id" returns="{ paths[], critical_resources[], orphaned_resources[], stats }" />

      <H2>Parameters</H2>
      <ParamList>
        <Param name="analysis_id" type="string" required>
          The ID returned by <A href="/docs/tools/scan"><Code>emfirge_scan</Code></A>.
        </Param>
      </ParamList>

      <H2>Example</H2>
      <CodeBlock
        tabs={[
          { label: "Ask", code: `How would an attacker get from the internet to my database?` },
          { label: "arguments", code: `{ "analysis_id": "7f3c9a2e-4b1d-4c8a-9f2e-1a2b3c4d5e6f" }` },
        ]}
      />

      <H2>Returns</H2>
      <CodeBlock
        numbered
        tabs={[{ label: "response", code: `{
  "paths": [
    {
      "finding_id": "EMFIRGE-EC2-002",
      "finding_title": "SSH port 22 is open to the entire internet (0.0.0.0/0)",
      "severity": "critical",
      "path": ["NAME_132", "NAME_140", "iam-role-AppServerRole", "acme-prod-customers"]
    }
  ],
  "critical_resources": [
    {
      "node_id": "acme-prod-customers",
      "label": "RDS: acme-prod-customers",
      "type": "rds_instance",
      "finding_count": 6,
      "max_severity": "Critical",
      "blast_radius": 22,
      "centrality": 0.15415,
      "exploit_distance": 6
    }
  ],
  "orphaned_resources": [
    { "id": "NAME_154", "type": "ebs_volume", "label": "EBS: 50GB",
      "estimated_monthly_cost": 5, "reason": "Unattached EBS volume (available state)" }
  ],
  "stats": {
    "total_nodes": 53, "total_edges": 88, "orphaned_count": 6,
    "estimated_monthly_waste": 43.65, "node_types": { }, "edge_types": { }
  }
}` }]}
      />
      <P>
        Each path exposes <Code>path</Code> (an ordered array of node IDs), <Code>severity</Code>, and the{" "}
        <Code>finding_id</Code> that produced it. <Code>critical_resources</Code> are your crown jewels,
        each scored by <Code>blast_radius</Code>, betweenness <Code>centrality</Code>, and{" "}
        <Code>exploit_distance</Code> (hops from the internet), the high-<Code>centrality</Code> entries
        are the <Strong>chokepoints</Strong> where hardening one resource kills the most paths.{" "}
        <Code>orphaned_resources</Code> and <Code>stats</Code> round out the graph. Some node IDs are
        raw graph labels (e.g. <Code>acme-prod-customers</Code>) rather than <Code>NAME_###</Code> tokens.
      </P>

      <Callout type="tip">
        Feed a chokepoint straight into{" "}
        <A href="/docs/tools/verify-fix"><Code>emfirge_verify_fix</Code></A>{" "}
        to prove that hardening it actually collapses those paths.
      </Callout>

      <PrevNext prev={prev} next={next} />
    </>
  );
}
