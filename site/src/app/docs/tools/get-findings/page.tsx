import { A, DocHeader, Lead, H2, P, Strong, Code, Badge, ParamList, Param, Callout, PrevNext, ToolSignature, SeverityLegend } from "@/components/docs/ui";
import { CodeBlock } from "@/components/docs/code-block";
import { EyeOff } from "lucide-react";
import { prevNext } from "@/lib/nav";

export const metadata = {
  title: "emfirge_get_findings · Emfirge Docs",
  description: "Get the full findings list for a scan, optionally filtered by severity.",
};

export default function Page() {
  const { prev, next } = prevNext("/docs/tools/get-findings");
  return (
    <>
      <DocHeader eyebrow="MCP Tools" title="emfirge_get_findings" mono>
        <Lead>
          Get the full findings list for a previous scan, optionally filtered by severity. Each
          finding carries its rule, the issue, a recommendation, the attack path, blast radius, and
          MITRE ATT&amp;CK mapping.
        </Lead>
        <div className="mt-5 flex flex-wrap gap-2">
          <Badge><EyeOff className="size-3.5" /> read-only</Badge>
          <Badge>no scan budget</Badge>
        </div>
      </DocHeader>

      <ToolSignature name="emfirge_get_findings" args="analysis_id, severity?" returns="{ critical_risks[], moderate_risks[], low_risks[] }" />
      <SeverityLegend />

      <H2>Parameters</H2>
      <ParamList>
        <Param name="analysis_id" type="string" required>
          The ID returned by <A href="/docs/tools/scan"><Code>emfirge_scan</Code></A>.
        </Param>
        <Param name="severity" type="Critical | Moderate | Low">
          Filter to one severity tier. Omit to get everything.
        </Param>
      </ParamList>

      <H2>Example</H2>
      <CodeBlock
        tabs={[
          { label: "Ask", code: `Show me just the critical findings from that scan` },
          { label: "arguments", code: `{
  "analysis_id": "7f3c9a2e-4b1d-4c8a-9f2e-1a2b3c4d5e6f",
  "severity": "Critical"
}` },
        ]}
      />

      <H2>Returns</H2>
      <CodeBlock
        numbered
        tabs={[{ label: "response", code: `{
  "critical_risks": [
    {
      "rule_id": "EMFIRGE-EC2-002",
      "category": "Security",
      "severity": "Critical",
      "confidence": "HIGH",
      "issue": "SSH port 22 is open to the entire internet (0.0.0.0/0)",
      "recommendation": "Restrict SSH access to your specific IP address only",
      "aws_service": "EC2",
      "resource_id": "NAME_132",
      "resource_type": "security_group",
      "region": "us-east-1",
      "attack_path": ["NAME_132", "NAME_140", "iam-role-AppServerRole", "acme-prod-customers"],
      "blast_radius": 15,
      "mitre_technique_id": "T1021.004",
      "mitre_technique_name": "Remote Services: SSH"
    }
  ]
}` }]}
      />
      <P>
        <Code>attack_path</Code> is an <Strong>array of node IDs</Strong> (not a string),{" "}
        <Code>blast_radius</Code> is an <Strong>integer</Strong> count of reachable resources, and MITRE
        is two fields, <Code>mitre_technique_id</Code> and <Code>mitre_technique_name</Code>. Some hops
        in <Code>attack_path</Code> may be un-tokenized graph labels (e.g. <Code>iam-role-AppServerRole</Code>).
      </P>

      <Callout type="note">
        Findings are grouped by severity into <Code>critical_risks</Code>, <Code>moderate_risks</Code>,
        and <Code>low_risks</Code> (a scan also returns <Code>best_practices</Code>,{" "}
        <Code>cost_findings</Code>, and <Code>toxic_combinations</Code>). An error means the{" "}
        <Code>analysis_id</Code> wasn&apos;t found, run a scan first.
      </Callout>

      <PrevNext prev={prev} next={next} />
    </>
  );
}
