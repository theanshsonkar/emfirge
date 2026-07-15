import { A, DocHeader, Lead, H2, P, Strong, Code, Callout, Steps, Step, PrevNext } from "@/components/docs/ui";
import { CodeBlock } from "@/components/docs/code-block";
import { prevNext } from "@/lib/nav";

export const metadata = {
  title: "Quickstart · Emfirge Docs",
  description: "Install the Emfirge MCP and run your first scan in under a minute.",
};

export default function Page() {
  const { prev, next } = prevNext("/docs/quickstart");
  return (
    <>
      <DocHeader eyebrow="Get Started" title="Quickstart">
        <Lead>Install the MCP, wire it into your AI client, and run your first scan in under a minute.</Lead>
      </DocHeader>

      <H2>1. Install</H2>
      <P>
        One command auto-detects and wires Emfirge into every MCP client on your machine, Claude
        Desktop, Cursor, Kiro, Cline, Continue, and Codex CLI.
      </P>
      <CodeBlock tabs={[{ label: "terminal", code: `npx @emfirge/mcp install` }]} />
      <P>
        It asks you to pick a <A href="/docs/privacy">privacy mode</A>,
        then writes the config. Skip the prompt in CI with <Code>--privacy=strict|balanced|off</Code>.
        Restart your client afterward so it picks up the new server.
      </P>

      <H2>2. Get a read-only role</H2>
      <P>
        Emfirge reads your account through a read-only IAM role you own. If you don&apos;t have one yet,
        just ask your assistant <Strong>&quot;help me set up Emfirge&quot;</Strong>, it calls{" "}
        <A href="/docs/tools/setup-help"><Code>emfirge_setup_help</Code></A>{" "}
        and hands you a one-click CloudFormation deploy link. See the{" "}
        <A href="/docs/security">Security model</A> for exactly what the role can do.
      </P>
      <Callout type="tip" title="Try it with zero setup">
        Use the demo role, fake infrastructure, the real engine:
        <div className="mt-2 font-mono text-[12.5px] text-foreground">
          arn:aws:iam::194722410583:role/EmfirgeReadOnly · region us-east-1
        </div>
      </Callout>

      <H2>3. Run your first scan</H2>
      <P>Restart your client, then just ask:</P>
      <CodeBlock
        tabs={[
          {
            label: "Ask",
            code: `Scan my AWS account, role
arn:aws:iam::123456789012:role/EmfirgeReadOnly, region us-east-1`,
          },
        ]}
      />
      <P>
        The scan takes 30-60 seconds. You get back a risk score, finding counts, and an{" "}
        <Code>analysis_id</Code> that every other tool uses. From there:
      </P>
      <Steps>
        <Step n={1} title="Explore findings">&quot;Show me the critical findings&quot; → <Code>emfirge_get_findings</Code>.</Step>
        <Step n={2} title="Walk attack paths">&quot;How would an attacker reach my database?&quot; → <Code>emfirge_attack_paths</Code>.</Step>
        <Step n={3} title="Prove a fix">&quot;Is it safe to close SSH on NAME_132?&quot; → <Code>emfirge_verify_fix</Code>.</Step>
      </Steps>

      <Callout type="note" title="Free tier">
        5 scans per day per AWS account, resets at midnight UTC. No signup, no API keys. Findings and
        the other tools (findings, attack paths, verify-fix, compliance) run against a completed scan
        and don&apos;t consume the daily scan budget.
      </Callout>

      <H2>Manual configuration</H2>
      <P>If auto-install can&apos;t find your client, add this to its MCP config by hand:</P>
      <CodeBlock
        tabs={[
          {
            label: "mcp.json",
            code: `{
  "mcpServers": {
    "emfirge": {
      "command": "npx",
      "args": ["-y", "@emfirge/mcp"],
      "env": { "EMFIRGE_PRIVACY": "strict" }
    }
  }
}`,
          },
        ]}
      />
      <Callout type="warning">
        MCP needs a desktop AI client (stdio transport). Web Claude / ChatGPT / Gemini don&apos;t
        support MCP yet, use the dashboard at app.emfirge.cloud for those.
      </Callout>

      <PrevNext prev={prev} next={next} />
    </>
  );
}
