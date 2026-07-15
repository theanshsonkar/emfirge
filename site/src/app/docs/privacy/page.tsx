import { DocHeader, Lead, H2, P, Strong, Code, Callout, PrevNext } from "@/components/docs/ui";
import { CodeBlock } from "@/components/docs/code-block";
import { prevNext } from "@/lib/nav";

export const metadata = {
  title: "Privacy modes · Emfirge Docs",
  description: "strict, balanced, and off: how Emfirge tokenizes AWS identifiers locally before your LLM sees them.",
};

function ModeRow({ mode, tokenized, best, def }: { mode: string; tokenized: string; best: string; def?: boolean }) {
  return (
    <div className="grid grid-cols-[6rem_1fr] gap-4 border-b border-border-soft py-4 sm:grid-cols-[8rem_1.3fr_1fr]">
      <div>
        <code className="font-mono text-[13px] font-medium text-foreground">{mode}</code>
        {def && <span className="ml-2 text-[10.5px] font-medium uppercase tracking-wide text-safe">Default</span>}
      </div>
      <div className="text-[13.5px] leading-relaxed text-muted-foreground">{tokenized}</div>
      <div className="text-[13px] leading-relaxed text-muted-foreground">{best}</div>
    </div>
  );
}

export default function Page() {
  const { prev, next } = prevNext("/docs/privacy");
  return (
    <>
      <DocHeader eyebrow="Privacy & Trust" title="Privacy modes">
        <Lead>
          In <Code>strict</Code> mode, the default, every AWS identifier is tokenized on your
          machine <Strong>before it reaches your LLM</Strong>. The mapping lives at{" "}
          <Code>~/.emfirge/tokens.json</Code> and is never sent to Emfirge, Anthropic, or anyone.
        </Lead>
      </DocHeader>

      <H2>How tokenization works</H2>
      <P>
        The MCP sits between your AI client and the Emfirge backend. On the way back from a scan, it
        replaces real IDs with stable tokens before the data reaches the model. When you say &quot;fix
        NAME_132&quot;, the MCP resolves the real ID locally, calls the backend, and re-tokenizes the
        response.
      </P>
      <CodeBlock
        tabs={[
          {
            label: "what's where",
            code: `# What the LLM sees (tokens are NAME_### / IP_###):
"NAME_132 has SSH open → reaches NAME_134"

# What stays on your disk (~/.emfirge/tokens.json):
NAME_132 = sg-0a1b2c3d
NAME_134 = acme-customer-pii`,
          },
        ]}
      />

      <H2>The three modes</H2>
      <div className="mt-4">
        <ModeRow mode="strict" def tokenized="Every AWS ID, ARNs, EC2/SG/IAM/S3, IPs, account IDs, bucket names." best="Banks, healthcare, regulated industries." />
        <ModeRow mode="balanced" tokenized="ARNs, EC2/SG/EIP/IAM IDs, IPs, account IDs. Subnets/VPCs/volumes stay raw." best="Most users." />
        <ModeRow mode="off" tokenized="Nothing, raw IDs go to the LLM." best="Personal accounts, demos, debugging." />
      </div>

      <H2>Changing modes</H2>
      <CodeBlock
        tabs={[
          {
            label: "terminal",
            code: `npx @emfirge/mcp privacy            # show current mode
npx @emfirge/mcp privacy strict     # change mode across every wired client`,
          },
        ]}
      />
      <P>You can also set it per client with the <Code>EMFIRGE_PRIVACY</Code> environment variable in the MCP config.</P>

      <H2>What the backend sees</H2>
      <Callout type="note" title="The honest note">
        Tokenization sits between the MCP and the LLM. The Emfirge backend <Strong>does</Strong>{" "}
        receive real IDs, it has to, in order to call AWS with your role. It stores them for 90 days,
        then auto-deletes. Wipe everything anytime with{" "}
        <Code>npx @emfirge/mcp purge --role-arn &lt;ARN&gt;</Code>.
      </Callout>
      <Callout type="warning" title="Graph labels can pass through un-tokenized">
        In testing, tool responses tokenize resource IDs to <Code>NAME_###</Code>, but some
        graph-derived values, attack-path hops and node labels like <Code>iam-role-AppServerRole</Code>,{" "}
        <Code>acme-prod-customers</Code>, or a secret name, can appear <Strong>un-tokenized</Strong> in{" "}
        <Code>attack_paths</Code> and <Code>simulate_breach</Code>. If you operate under strict data
        rules, review those two tools&apos; output before sharing a transcript.
      </Callout>

      <PrevNext prev={prev} next={next} />
    </>
  );
}
