import { A, DocHeader, Lead, H2, P, Strong, Code, Param, ParamList, Callout, PrevNext } from "@/components/docs/ui";
import { CodeBlock } from "@/components/docs/code-block";
import { prevNext } from "@/lib/nav";

export const metadata = {
  title: "Self-hosting · Emfirge Docs",
  description: "Point the MCP at your own backend with EMFIRGE_BASE_URL, and every environment variable it reads.",
};

export default function Page() {
  const { prev, next } = prevNext("/docs/self-host");
  return (
    <>
      <DocHeader eyebrow="Privacy & Trust" title="Self-hosting">
        <Lead>
          The MCP talks to the hosted backend at <Code>emfirge.cloud</Code> over HTTPS by default.
          Point it at your own deployment by overriding one environment variable, no code changes.
        </Lead>
      </DocHeader>

      <H2>Point at your own backend</H2>
      <P>
        Set <Code>EMFIRGE_BASE_URL</Code> in the MCP server config for each client. The MCP is a thin
        client, it calls the backend&apos;s endpoints and tokenizes responses locally, so a
        self-hosted backend behaves identically.
      </P>
      <CodeBlock
        tabs={[
          {
            label: "mcp.json",
            code: `{
  "mcpServers": {
    "emfirge": {
      "command": "npx",
      "args": ["-y", "@emfirge/mcp"],
      "env": {
        "EMFIRGE_BASE_URL": "https://emfirge.internal.acme.com/api",
        "EMFIRGE_PRIVACY": "strict"
      }
    }
  }
}`,
          },
        ]}
      />
      <Callout type="tip">
        The web dashboard URL is derived from the API base, <Code>…/api</Code> is stripped, so
        verify-fix &quot;open a PR&quot; links point at your own domain automatically.
      </Callout>

      <H2>Environment variables</H2>
      <ParamList>
        <Param name="EMFIRGE_BASE_URL" type="url">
          Backend URL. Default <Code>https://emfirge.cloud/api</Code>. Override to self-host.
        </Param>
        <Param name="EMFIRGE_PRIVACY" type="strict | balanced | off">
          Tokenization mode. Default <Code>strict</Code>. See{" "}
          <A href="/docs/privacy">Privacy modes</A>.
        </Param>
        <Param name="EMFIRGE_TRUSTED_ACCOUNT_ID" type="string">
          AWS account ID the generated IAM role trusts. Default <Code>282027772803</Code>. Set this to
          your own account when self-hosting so <Code>setup_help</Code> builds a role that trusts your scanner.
        </Param>
        <Param name="EMFIRGE_EXTERNAL_ID" type="string">
          ExternalId required in the role&apos;s trust policy. Default <Code>aws-risk-agent</Code>.
        </Param>
        <Param name="EMFIRGE_TEMPLATE_URL" type="url">
          CloudFormation template URL used by <Code>setup_help</Code>. Override to ship your own role template.
        </Param>
      </ParamList>

      <Callout type="note" title="Open source">
        The MCP and a public mirror of the backend are open source under BUSL 1.1 (free for
        non-production and small production use; converts to Apache 2.0 in 2030).
      </Callout>

      <PrevNext prev={prev} next={next} />
    </>
  );
}
