import { A, DocHeader, Lead, H2, P, Strong, Code, Badge, ParamList, Param, Callout, PrevNext, ToolSignature } from "@/components/docs/ui";
import { CodeBlock } from "@/components/docs/code-block";
import { EyeOff } from "lucide-react";
import { prevNext } from "@/lib/nav";

export const metadata = { title: "emfirge_create_branch · Emfirge Docs", description: "Create an isolated infrastructure branch from a completed analysis." };

export default function Page() {
  const { prev, next } = prevNext("/docs/tools/create-branch");
  return <><DocHeader eyebrow="MCP Tools · Branch" title="emfirge_create_branch" mono><Lead>Create an isolated infrastructure branch from a completed analysis. Use it to model changes safely before applying anything to AWS.</Lead><div className="mt-5 flex flex-wrap gap-2"><Badge><EyeOff className="size-3.5" /> modeled only</Badge><Badge>no AWS changes</Badge></div></DocHeader>
    <ToolSignature name="emfirge_create_branch" args="base_analysis_id, name" returns="{ branch_id }" />
    <H2>Parameters</H2><ParamList><Param name="base_analysis_id" type="string" required>The analysis ID returned by <A href="/docs/tools/scan"><Code>emfirge_scan</Code></A>. The branch starts from that completed snapshot.</Param><Param name="name" type="string" required>A human-readable name for the branch.</Param></ParamList>
    <H2>Example</H2><CodeBlock tabs={[{ label: "arguments", code: `{"base_analysis_id":"analysis_123","name":"restrict-public-access"}` }]} />
    <H2>Returns</H2><CodeBlock tabs={[{ label: "response", code: `{"branch_id":"branch_456"}` }]} /><P>The returned <Code>branch_id</Code> identifies the isolated model for <A href="/docs/tools/apply-change"><Code>emfirge_apply_change</Code></A>, diff, verdict, rollback, discard, and comparison calls. The base snapshot remains immutable; this operation does not mutate AWS.</P>
    <Callout type="note" title="A branch is a model"><Strong>Create branch</Strong> forks saved scan data for analysis. It does not assume write permissions or make changes in your AWS account.</Callout><PrevNext prev={prev} next={next} /></>;
}
