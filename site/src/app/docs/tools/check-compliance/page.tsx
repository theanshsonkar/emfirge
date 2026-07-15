import { A, DocHeader, Lead, H2, P, Code, Badge, ParamList, Param, Callout, PrevNext, ToolSignature } from "@/components/docs/ui";
import { CodeBlock } from "@/components/docs/code-block";
import { EyeOff } from "lucide-react";
import { prevNext } from "@/lib/nav";

export const metadata = {
  title: "emfirge_check_compliance · Emfirge Docs",
  description: "CIS AWS Foundations 1.5 or SOC 2 per-control pass/fail, with the findings that triggered each failure.",
};

export default function Page() {
  const { prev, next } = prevNext("/docs/tools/check-compliance");
  return (
    <>
      <DocHeader eyebrow="MCP Tools" title="emfirge_check_compliance" mono>
        <Lead>
          Get CIS AWS Foundations 1.5 or SOC 2 status for a scan, per-control pass/fail, with the
          specific findings that triggered each failure so you know exactly what to fix.
        </Lead>
        <div className="mt-5 flex flex-wrap gap-2">
          <Badge><EyeOff className="size-3.5" /> read-only</Badge>
          <Badge>CIS 1.5 · SOC 2</Badge>
        </div>
      </DocHeader>

      <ToolSignature name="emfirge_check_compliance" args="analysis_id, framework?" returns="{ frameworks[], fired_rule_ids[] }" />

      <H2>Parameters</H2>
      <ParamList>
        <Param name="analysis_id" type="string" required>
          The ID returned by <A href="/docs/tools/scan"><Code>emfirge_scan</Code></A>.
        </Param>
        <Param name="framework" type="cis-aws-1.5 | soc2">
          Filter to one framework. Omit to get both.
        </Param>
      </ParamList>

      <H2>Example</H2>
      <CodeBlock
        tabs={[
          { label: "Ask", code: `How do I score against CIS AWS 1.5 on that scan?` },
          { label: "arguments", code: `{
  "analysis_id": "7f3c9a2e-4b1d-4c8a-9f2e-1a2b3c4d5e6f",
  "framework": "cis-aws-1.5"
}` },
        ]}
      />

      <H2>Returns</H2>
      <CodeBlock
        numbered
        tabs={[{ label: "response", code: `{
  "analysis_id": "7f3c9a2e-4b1d-4c8a-9f2e-1a2b3c4d5e6f",
  "frameworks": [
    {
      "id": "cis-aws-1.5",
      "name": "CIS AWS Foundations",
      "version": "1.5",
      "totalControls": 29,
      "passedControls": 5,
      "failedControls": 24,
      "naControls": 0,
      "sections": [ { "id": "1", "title": "Identity and Access Management" } ],
      "controls": [
        {
          "id": "1.2",
          "title": "Ensure MFA enabled for all IAM users",
          "section": "1",
          "status": "fail",
          "mappedRuleId": "EMFIRGE-IAM-003",
          "description": "Users without MFA detected"
        }
      ]
    }
  ],
  "fired_rule_ids": ["EMFIRGE-EC2-002", "EMFIRGE-IAM-003", "…"]
}` }]}
      />
      <P>
        The top level is a <Code>frameworks</Code> array (both CIS 1.5 and SOC 2 unless you filter).
        Each framework reports <Code>totalControls</Code>/<Code>passedControls</Code>/<Code>failedControls</Code>
        and a <Code>controls</Code> list; every control links to a single <Code>mappedRuleId</Code>, and{" "}
        <Code>fired_rule_ids</Code> lists every rule that triggered. CIS 1.5 has 29 controls, SOC 2 has 12.
      </P>

      <Callout type="note">
        Every failed control links back to the rule that caused it via <Code>mappedRuleId</Code>, and
        each finding carries a MITRE ATT&amp;CK mapping, so a compliance gap traces straight to a
        concrete, fixable issue.
      </Callout>

      <PrevNext prev={prev} next={next} />
    </>
  );
}
