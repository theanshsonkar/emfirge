import { A, DocHeader, Lead, H2, P, Strong, Code, Badge, ParamList, Param, Callout, PrevNext, ToolSignature } from "@/components/docs/ui";
import { CodeBlock } from "@/components/docs/code-block";
import { Cpu, EyeOff } from "lucide-react";
import { prevNext } from "@/lib/nav";

export const metadata = {
  title: "emfirge_verify_fix · Emfirge Docs",
  description: "Simulate fixing a finding on a clone of your graph and read back the risk delta. No AWS changes.",
};

export default function Page() {
  const { prev, next } = prevNext("/docs/tools/verify-fix");
  return (
    <>
      <DocHeader eyebrow="MCP Tools" title="emfirge_verify_fix" mono>
        <Lead>
          Simulate fixing a finding <Strong>without applying any change</Strong>. Emfirge clones the
          graph, applies the rule&apos;s mutation, rebuilds, re-runs every rule, and returns the score
          delta plus which other findings resolve. This is the fork.
        </Lead>
        <div className="mt-5 flex flex-wrap gap-2">
          <Badge><Cpu className="size-3.5" /> deterministic</Badge>
          <Badge><EyeOff className="size-3.5" /> no AWS changes</Badge>
        </div>
      </DocHeader>

      <ToolSignature name="emfirge_verify_fix" args="rule_id, resource_id, analysis_id" returns="{ can_simulate, findings_removed[], score_before, score_after, safe_to_apply }" />

      <H2>Parameters</H2>
      <ParamList>
        <Param name="rule_id" type="string" required>
          The finding&apos;s rule, full or short form, <Code>EMFIRGE-EC2-002</Code> or <Code>EC2-002</Code>.
        </Param>
        <Param name="resource_id" type="string" required>
          The resource the fix targets, a raw ID (<Code>sg-0a1b2c3d</Code>) or a token from a previous
          response (<Code>NAME_132</Code>). Tokens are expanded locally.
        </Param>
        <Param name="analysis_id" type="string" required>
          The ID returned by <A href="/docs/tools/scan"><Code>emfirge_scan</Code></A>.
        </Param>
      </ParamList>

      <H2>Example</H2>
      <CodeBlock
        tabs={[
          { label: "Ask", code: `Is it safe to close SSH on NAME_132? (rule EC2-002)` },
          { label: "arguments", code: `{
  "rule_id": "EC2-002",
  "resource_id": "NAME_132",
  "analysis_id": "7f3c9a2e-4b1d-4c8a-9f2e-1a2b3c4d5e6f"
}` },
        ]}
      />

      <H2>Returns</H2>
      <CodeBlock
        numbered
        tabs={[{ label: "response", code: `{
  "can_simulate": true,
  "findings_removed": [ { "rule_id": "EMFIRGE-EC2-002", "severity": "Critical", /* … */ } ],
  "findings_added": [],
  "toxic_combos_resolved": ["SSH_OPEN_NO_GUARDDUTY"],
  "toxic_combos_created": [],
  "score_before": 3,
  "score_after": 3,
  "score_delta": 0,
  "safe_to_apply": true
}` }]}
        footer={<><span className="font-medium" style={{ color: "var(--safe)" }}>✓ safe to apply</span><span>· removes 1 critical + a toxic combo, adds 0.</span></>}
      />
      <P>
        <Code>findings_removed</Code> and <Code>findings_added</Code> are <Strong>arrays of full finding
        objects</Strong>, not counts. <Code>score_before</Code>/<Code>score_after</Code> are the 0-100
        posture score (higher is safer); here it stays <Code>3</Code> because 14 other criticals still
        dominate, yet the fix is still safe, it removed a finding and a toxic combo and added none.
      </P>

      <H2>What it can simulate</H2>
      <P>Deterministic fix-simulation covers these rules today:</P>
      <CodeBlock tabs={[{ label: "simulatable rules", code: `EC2-002  EC2-003  EC2-009
S3-001   S3-002   S3-003
RDS-002  RDS-003  RDS-004  RDS-006
WAF-001  GUARD-001  CW-001` }]} />
      <P>
        For any other finding the tool returns guidance instead of a bare result: ask it to generate
        the Terraform, or open the scan in the dashboard to raise a pull request automatically.
      </P>

      <Callout type="note" title="Opening pull requests is web-only for now">
        Over MCP, Emfirge <Strong>maps, simulates, and verifies</Strong> fixes, it does not open pull
        requests yet. Raising the Terraform PR (surgical diff on your <Code>.tf</Code>, feature branch,
        finding linked) currently happens in the <A href="https://app.emfirge.cloud">Emfirge web app</A>.
        MCP-native PR creation is on the roadmap.
      </Callout>

      <Callout type="warning" title="What 'safe' means">
        <Code>safe_to_apply</Code> is true when the change opens <Strong>no new security finding</Strong>{" "}
        and doesn&apos;t worsen the score. It does not verify application connectivity, and it mutates
        your <Strong>last scan</Strong>, re-scan first if the account changed. See{" "}
        <A href="/docs/how-it-works">How the fork works</A>.
      </Callout>

      <PrevNext prev={prev} next={next} />
    </>
  );
}
