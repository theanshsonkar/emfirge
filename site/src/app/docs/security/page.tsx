import { DocHeader, Lead, H2, P, Strong, Code, Steps, Step, Callout, PrevNext } from "@/components/docs/ui";
import { CodeBlock } from "@/components/docs/code-block";
import { prevNext } from "@/lib/nav";

export const metadata = {
  title: "Security model · Emfirge Docs",
  description: "Read-only IAM role, ExternalId, scoped trust, 1-hour STS credentials, 90-day TTL, instant revoke.",
};

export default function Page() {
  const { prev, next } = prevNext("/docs/security");
  return (
    <>
      <DocHeader eyebrow="Privacy & Trust" title="Security model">
        <Lead>
          Emfirge reads your account through a <Strong>read-only IAM role you own and control</Strong>.
          No write permissions of any kind, scoped trust, temporary credentials, and one-click revoke.
        </Lead>
      </DocHeader>

      <H2>The role</H2>
      <P>
        Setup deploys a CloudFormation stack that creates a role granting AWS&apos;s managed{" "}
        <Code>SecurityAudit</Code> policy plus a small set of extra read permissions. It has{" "}
        <Strong>no write access</Strong>, the engine can look, never touch.
      </P>
      <ul className="mt-4 space-y-2 text-[14px] text-muted-foreground">
        <li>• <Strong>Read-only</Strong>, zero write permissions.</li>
        <li>• <Strong>ExternalId</Strong>, <Code>aws-risk-agent</Code>, prevents confused-deputy attacks.</li>
        <li>• <Strong>Scoped trust</Strong>, only Emfirge&apos;s AWS account (<Code>282027772803</Code>) can assume it.</li>
        <li>• <Strong>STS, 1-hour</Strong>, temporary credentials that expire in an hour and are never stored.</li>
        <li>• <Strong>Instant revoke</Strong>, delete the CloudFormation stack and all access is gone.</li>
      </ul>

      <H2>Setting it up</H2>
      <P>Ask your assistant &quot;help me set up Emfirge&quot; to get a pre-filled deploy link, then:</P>
      <Steps>
        <Step n={1} title="Open the deploy URL">The AWS console loads with the CloudFormation form pre-filled.</Step>
        <Step n={2} title="Acknowledge & create">Tick the IAM-resources checkbox and create the stack (~30s).</Step>
        <Step n={3} title="Copy the RoleArn">From the stack&apos;s Outputs tab, it starts with <Code>arn:aws:iam::</Code>.</Step>
        <Step n={4} title="Paste it back">Hand the ARN to your assistant and the scan runs.</Step>
      </Steps>

      <H2>Deterministic backend</H2>
      <P>
        No LLM runs in the scoring or fix-simulation path. Scanning, rules, graph analysis, and
        verify-fix are pure computation, the same input always yields the same output. Prose
        summaries (when generated) are the only place a model is used, and never inside the MCP path.
      </P>

      <H2>Data retention</H2>
      <Callout type="note">
        The backend receives real resource IDs (it must, to call AWS) and stores scan data for{" "}
        <Strong>90 days</Strong>, then auto-deletes. Wipe it immediately at any time:
      </Callout>
      <CodeBlock tabs={[{ label: "terminal", code: `npx @emfirge/mcp purge --role-arn <ARN>` }]} />

      <H2>Common errors</H2>
      <ul className="mt-4 space-y-2 text-[14px] text-muted-foreground">
        <li>• <Code>403</Code>, access denied. Check the role&apos;s trust policy and ExternalId <Code>aws-risk-agent</Code>. No role yet? Ask for setup help.</li>
        <li>• <Code>404</Code>, an <Code>analysis_id</Code> wasn&apos;t found. Run <Code>emfirge_scan</Code> first.</li>
        <li>• <Code>429</Code>, daily scan limit reached (5/day per account). Resets at midnight UTC.</li>
      </ul>

      <PrevNext prev={prev} next={next} />
    </>
  );
}
