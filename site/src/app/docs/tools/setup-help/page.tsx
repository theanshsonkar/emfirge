import { A, DocHeader, Lead, H2, P, Strong, Code, Badge, Callout, Steps, Step, PrevNext, ToolSignature } from "@/components/docs/ui";
import { CodeBlock } from "@/components/docs/code-block";
import { Wrench } from "lucide-react";
import { prevNext } from "@/lib/nav";

export const metadata = {
  title: "emfirge_setup_help · Emfirge Docs",
  description: "Returns a one-click CloudFormation deploy URL for the read-only IAM role. Takes no parameters.",
};

export default function Page() {
  const { prev, next } = prevNext("/docs/tools/setup-help");
  return (
    <>
      <DocHeader eyebrow="MCP Tools" title="emfirge_setup_help" mono>
        <Lead>
          Returns a ready-to-click AWS CloudFormation deploy URL that creates the read-only IAM role
          Emfirge needs. Call this when you don&apos;t have a role ARN yet, or when a scan returns a{" "}
          <Code>403</Code>. Takes <Strong>no parameters</Strong>.
        </Lead>
        <div className="mt-5 flex flex-wrap gap-2">
          <Badge><Wrench className="size-3.5" /> setup</Badge>
          <Badge>no parameters</Badge>
        </div>
      </DocHeader>

      <ToolSignature name="emfirge_setup_help" args="" returns="CloudFormation deploy URL + setup steps" />

      <H2>Example</H2>
      <CodeBlock tabs={[{ label: "Ask", code: `Help me set up Emfirge` }]} />

      <H2>Returns</H2>
      <P>A CloudFormation quick-create URL, pre-filled with the ExternalId, plus step-by-step instructions:</P>
      <CodeBlock
        tabs={[{ label: "response", code: `Deploy URL: https://console.aws.amazon.com/cloudformation/home
#/stacks/quickcreate?templateURL=…&stackName=EmfirgeReadOnlyStack
&param_ExternalId=aws-risk-agent

1. Open the URL, the console loads the form pre-filled.
2. Tick "I acknowledge…IAM resources" and Create stack (~30s).
3. On CREATE_COMPLETE, copy the RoleArn from the Outputs tab.
4. Paste the RoleArn back here and the scan runs.` }]}
      />

      <H2>Then run a scan</H2>
      <Steps>
        <Step n={1} title="Copy the RoleArn">From the stack&apos;s Outputs tab, starts with <Code>arn:aws:iam::</Code>.</Step>
        <Step n={2} title="Hand it to your assistant">Along with a region, and <Code>emfirge_scan</Code> takes over.</Step>
      </Steps>

      <Callout type="warning" title="CLI clients hide tool output">
        In terminal clients (Claude Code, Codex CLI, Kiro CLI), tool output is hidden by default. The
        tool instructs the assistant to <Strong>paste the deploy URL verbatim</Strong>, if you only
        see &quot;click the link above&quot; with no link, ask it to print the URL.
      </Callout>

      <Callout type="note">
        The role trusts account <Code>282027772803</Code> with ExternalId <Code>aws-risk-agent</Code>.
        Self-hosting? Override those via <Code>EMFIRGE_TRUSTED_ACCOUNT_ID</Code> and{" "}
        <Code>EMFIRGE_EXTERNAL_ID</Code>, see{" "}
        <A href="/docs/self-host">Self-hosting</A>.
      </Callout>

      <PrevNext prev={prev} next={next} />
    </>
  );
}
