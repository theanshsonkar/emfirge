import { A, DocHeader, Lead, H2, P, Strong, Code, Badge, ParamList, Param, Callout, PrevNext, ToolSignature } from "@/components/docs/ui";
import { CodeBlock } from "@/components/docs/code-block";
import { Cpu, EyeOff } from "lucide-react";
import { prevNext } from "@/lib/nav";

export const metadata = {
  title: "emfirge_scan · Emfirge Docs",
  description: "Scan an AWS account through a read-only role. Returns a risk score, finding counts, and an analysis_id.",
};

export default function Page() {
  const { prev, next } = prevNext("/docs/tools/scan");
  return (
    <>
      <DocHeader eyebrow="MCP Tools" title="emfirge_scan" mono>
        <Lead>
          Scan an AWS account for security risks. Returns an <Code>overall_risk_score</Code> (0-100,
          where <Strong>higher is safer</Strong>) with a matching <Code>overall_risk_level</Code>,
          per-category scores, grouped findings, and an <Code>analysis_id</Code> the other tools use.
          Resource IDs are tokenized to <Code>NAME_###</Code> by default.
        </Lead>
        <div className="mt-5 flex flex-wrap gap-2">
          <Badge><Cpu className="size-3.5" /> deterministic</Badge>
          <Badge><EyeOff className="size-3.5" /> read-only</Badge>
          <Badge>5 / day per account</Badge>
        </div>
      </DocHeader>

      <ToolSignature name="emfirge_scan" args="role_arn, region" returns="{ overall_risk_score, overall_risk_level, analysis_id, critical_risks[], … }" />

      <H2>Parameters</H2>
      <ParamList>
        <Param name="role_arn" type="string" required>
          The IAM role ARN to assume, must match <Code>arn:aws:iam::&lt;account&gt;:role/&lt;name&gt;</Code> and
          trust Emfirge&apos;s account with ExternalId <Code>aws-risk-agent</Code>. No role yet? See{" "}
          <A href="/docs/tools/setup-help"><Code>emfirge_setup_help</Code></A>.
        </Param>
        <Param name="region" type="string" required>
          The AWS region to scan (e.g. <Code>us-east-1</Code>, <Code>ap-south-1</Code>). There is{" "}
          <Strong>no default</Strong>, most AWS resources are region-specific, so scanning the wrong
          region returns zero findings on a busy account. If you&apos;re unsure which region, ask before scanning.
        </Param>
      </ParamList>

      <H2>Example</H2>
      <CodeBlock
        tabs={[
          { label: "Ask", code: `Scan my AWS account, role
arn:aws:iam::123456789012:role/EmfirgeReadOnly, region us-east-1` },
          { label: "arguments", code: `{
  "role_arn": "arn:aws:iam::123456789012:role/EmfirgeReadOnly",
  "region": "us-east-1"
}` },
        ]}
      />

      <H2>Returns</H2>
      <CodeBlock
        numbered
        tabs={[{ label: "response", code: `{
  "analysis_id": "7f3c9a2e-4b1d-4c8a-9f2e-1a2b3c4d5e6f",
  "region_analyzed": "us-east-1",
  "overall_risk_score": 3,
  "overall_risk_level": "CRITICAL",
  "security_score": 18,
  "availability_score": 96,
  "disaster_recovery_score": 90,
  "cost_score": 97,
  "simulation_baseline": { "critical_count": 15, "moderate_count": 17 },
  "critical_risks": [ /* … full finding objects … */ ],
  "moderate_risks": [ /* … */ ],
  "low_risks": [ /* … */ ],
  "toxic_combinations": [ /* … */ ],
  "total_resources_scanned": 51
}` }]}
        footer={<span>The result ends with a line like <Code>Scans remaining today: 4/5</Code>.</span>}
      />
      <P>
        <Code>overall_risk_score</Code> is a 0-100 posture score where <Strong>higher is safer</Strong>{" "}
        (this demo account scores <Code>3</Code> → <Code>CRITICAL</Code>). Findings arrive already grouped
        into <Code>critical_risks</Code>, <Code>moderate_risks</Code>, and <Code>low_risks</Code> arrays.
        There is no separate counts object; tallies live under <Code>simulation_baseline</Code>.
      </P>
      <P>
        Hold on to the <Code>analysis_id</Code>, <Code>get_findings</Code>, <Code>attack_paths</Code>,{" "}
        <Code>verify_fix</Code>, <Code>simulate_breach</Code>, and <Code>check_compliance</Code> all take it.
      </P>

      <Callout type="note" title="Timing & limits">
        A scan takes 30-60 seconds on a real account (the tool streams to stay under proxy timeouts).
        Free tier is 5 scans/day per AWS account, resetting at midnight UTC, a <Code>429</Code> means
        you&apos;ve hit it. The other tools run against a completed scan and don&apos;t consume the budget.
      </Callout>

      <PrevNext prev={prev} next={next} />
    </>
  );
}
