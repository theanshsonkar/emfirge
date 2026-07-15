import { A, DocHeader, Lead, H2, P, Code, Param, ParamList, Callout, PrevNext } from "@/components/docs/ui";
import { CodeBlock } from "@/components/docs/code-block";
import { prevNext } from "@/lib/nav";

export const metadata = {
  title: "CLI reference · Emfirge Docs",
  description: "Every npx @emfirge/mcp subcommand: install, uninstall, status, privacy, tokens, purge.",
};

export default function Page() {
  const { prev, next } = prevNext("/docs/cli");
  return (
    <>
      <DocHeader eyebrow="Get Started" title="CLI reference">
        <Lead>
          The same package that runs the MCP server is also a small CLI. With no subcommand it runs
          as an MCP stdio server for your AI client; with a subcommand it manages your install.
        </Lead>
      </DocHeader>

      <H2>Commands</H2>
      <CodeBlock
        tabs={[
          {
            label: "terminal",
            code: `npx @emfirge/mcp install                       # wire into all detected clients
npx @emfirge/mcp install --privacy=balanced    # non-interactive: skip the prompt
npx @emfirge/mcp uninstall                      # remove from all clients
npx @emfirge/mcp status                         # wired clients, backend URL, privacy mode
npx @emfirge/mcp privacy                         # show current privacy mode
npx @emfirge/mcp privacy strict|balanced|off     # set privacy mode everywhere
npx @emfirge/mcp tokens                          # list local token mappings
npx @emfirge/mcp purge --role-arn <ARN>          # delete all your scan data (local + server)
npx @emfirge/mcp --version                        # print version
npx @emfirge/mcp --help                           # print usage`,
          },
        ]}
      />

      <H2>install</H2>
      <P>
        Detects Claude Desktop, Cursor, Kiro, Cline, Continue, and Codex CLI, and adds the{" "}
        <Code>emfirge</Code> server to each config it finds. Prompts for a privacy mode unless you
        pass <Code>--privacy</Code>.
      </P>
      <ParamList>
        <Param name="--privacy" type="strict | balanced | off" >
          Set the mode non-interactively. Useful in scripts and CI. Defaults to <Code>strict</Code>.
        </Param>
      </ParamList>

      <H2>status</H2>
      <P>Prints which clients are wired, the backend URL in use, and the active privacy mode. Run it if a scan isn&apos;t showing up in your client.</P>

      <H2>privacy</H2>
      <P>
        With no argument, prints the current mode. With <Code>strict</Code>, <Code>balanced</Code>,
        or <Code>off</Code>, updates the mode across every wired client at once. See{" "}
        <A href="/docs/privacy">Privacy modes</A>.
      </P>

      <H2>tokens</H2>
      <P>
        Lists the local token → real-ID mappings stored at <Code>~/.emfirge/tokens.json</Code>. This
        file never leaves your machine.
      </P>

      <H2>purge</H2>
      <P>Deletes all of your scan data, both the local token map and the server-side records for the given role.</P>
      <ParamList>
        <Param name="--role-arn" type="string" required>
          The role ARN whose data should be wiped.
        </Param>
      </ParamList>
      <Callout type="warning" title="Irreversible">
        <Code>purge</Code> permanently deletes scan records for that account. There is no undo.
      </Callout>

      <PrevNext prev={prev} next={next} />
    </>
  );
}
