import { A, DocHeader, Lead, H2, P, Strong, Code, Badge, ParamList, Param, Callout, PrevNext, ToolSignature } from "@/components/docs/ui";
import { CodeBlock } from "@/components/docs/code-block";
import { EyeOff } from "lucide-react";
import { prevNext } from "@/lib/nav";

export const metadata = {
  title: "emfirge_simulate_breach · Emfirge Docs",
  description: "Walk a full kill chain end-to-end from a natural-language what-if. Entry, pivot, impact, blast radius.",
};

export default function Page() {
  const { prev, next } = prevNext("/docs/tools/simulate-breach");
  return (
    <>
      <DocHeader eyebrow="MCP Tools" title="emfirge_simulate_breach" mono>
        <Lead>
          Walk a full kill chain end-to-end against the graph. Give it a natural-language scenario or
          &quot;what if&quot;, and it returns a verdict, severity, and every stage of the attack:{" "}
          <Strong>entry → pivot → impact</Strong>, plus blast radius and follow-up moves.
        </Lead>
        <div className="mt-5 flex flex-wrap gap-2">
          <Badge><EyeOff className="size-3.5" /> read-only</Badge>
          <Badge>what-if</Badge>
        </div>
      </DocHeader>

      <ToolSignature name="emfirge_simulate_breach" args="query, analysis_id" returns="{ verdict, severity, stages[], blast_radius, follow_up }" />

      <H2>Parameters</H2>
      <ParamList>
        <Param name="query" type="string" required>
          The scenario, 3-500 characters. Examples: <Code>&quot;what gets exposed if NAME_132 opens port 80&quot;</Code>,{" "}
          <Code>&quot;show the worst attack path&quot;</Code>. Tokens like <Code>NAME_132</Code> are expanded locally.
        </Param>
        <Param name="analysis_id" type="string" required>
          The ID returned by <A href="/docs/tools/scan"><Code>emfirge_scan</Code></A>.
        </Param>
      </ParamList>

      <H2>Example</H2>
      <CodeBlock
        tabs={[
          { label: "Ask", code: `What gets exposed if NAME_132 opens port 80 to the world?` },
          { label: "arguments", code: `{
  "query": "what gets exposed if NAME_132 opens port 80",
  "analysis_id": "7f3c9a2e-4b1d-4c8a-9f2e-1a2b3c4d5e6f"
}` },
        ]}
      />

      <H2>Returns</H2>
      <CodeBlock
        numbered
        tabs={[{ label: "response", code: `{
  "verdict": "Full data exfiltration path exists. 1 database, 1 S3 bucket, 1 secret reachable from the internet in 7 hops.",
  "severity": "critical",
  "summary": "An attacker can reach your data stores in 7 hops…",
  "stages": [
    { "order": 1, "caption": "Attacker lands on EC2: NAME_138 via open security group",
      "node_ids": ["NAME_138", "NAME_139", "NAME_140"], "color": "red" },
    { "order": 2, "caption": "EC2: NAME_138 assumes IAM Role: AppServerRole, credential theft possible",
      "node_ids": ["iam-role-AppServerRole"], "color": "red" },
    { "order": 3, "caption": "IAM role accesses RDS: acme-prod-customers, data exfiltration risk",
      "node_ids": ["acme-prod-customers"], "color": "amber" }
  ],
  "blast_radius": { "total": 23, "by_type": { "EC2": 7, "SG": 5, "RDS": 1, "S3": 1 } },
  "follow_up": "What specific data can be exfiltrated from the exposed storage?",
  "category": "attack_surface"
}` }]}
      />
      <P>
        <Code>stages</Code> carry <Code>order</Code>, a human <Code>caption</Code>, the affected{" "}
        <Code>node_ids</Code>, and a <Code>color</Code> (<Code>red</Code>/<Code>amber</Code>), the
        entry→pivot→impact progression is conveyed by order and color, not a <Code>phase</Code> field.{" "}
        <Code>blast_radius</Code> is an object with a <Code>total</Code> and a <Code>by_type</Code> tally,
        and <Code>follow_up</Code> is a single suggested next question.
      </P>

      <Callout type="note">
        In MCP mode the backend skips its prose summary (your host LLM writes that), so the result is
        deterministic and returns in a few seconds. It&apos;s read-only, nothing changes in AWS.
      </Callout>

      <PrevNext prev={prev} next={next} />
    </>
  );
}
