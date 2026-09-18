import { A, DocHeader, Lead, H2, P, Strong, Code, CardGrid, Card, Callout, PrevNext } from "@/components/docs/ui";
import { CodeBlock } from "@/components/docs/code-block";
import { HarnessDiagram } from "@/components/docs/harness-diagram";
import { prevNext } from "@/lib/nav";
import DocsLayout from "./docs/layout";

export const metadata = {
  title: "Emfirge — The harness between AI and cloud",
  description:
    "Give your AI agent a safe branch of your cloud before anything touches production.",
};

export default function Page() {
  const { prev, next } = prevNext("/");
  return (
    <DocsLayout>
      <>
      <DocHeader eyebrow="Get Started · AI × Cloud" title="The harness between AI and cloud">
        <Lead>
          AI agents are good at proposing infrastructure changes. Clouds are not good places to let them
          experiment directly. Emfirge is the <Strong>harness in between</Strong>: a safe, branchable copy
          of your cloud where an agent can try a change, inspect the consequences, and earn a verdict before
          anything touches production.
        </Lead>
      </DocHeader>

      <HarnessDiagram />

      <Callout type="note" title="Give your agent a branch, not your keys">
        Emfirge keeps the live cloud read-only and turns each proposed change into a modeled branch. The
        agent can explore security, reachability, cost, limits, and blast radius without getting a direct
        path to production.
      </Callout>

      <H2>What it does</H2>
      <P>
        Your AI assistant can read your code, but it can&apos;t see your cloud, so it can&apos;t tell
        you whether a change might affect your security posture. Emfirge closes that gap. It runs next to your assistant (Claude,
        Cursor, Kiro, and others), maps your AWS account through a <Strong>read-only</Strong> role
        into one connected graph, and lets your assistant answer the question that actually matters:{" "}
        <Strong>&quot;what happens if I make this change?&quot;</Strong>
      </P>
      <P>
        You ask in plain language. Behind the scenes, Emfirge copies your cloud&apos;s layout, applies
        the change to the copy, and re-checks everything, then tells you what it fixed and whether it
        opened anything new. <Strong>Your real AWS account is never touched.</Strong>
      </P>

      <CodeBlock
        tabs={[
          {
            label: "Ask",
            code: `You: Scan my AWS account, role
arn:aws:iam::123456789012:role/EmfirgeReadOnly, region us-east-1

Emfirge → risk 3/100 (CRITICAL, higher is safer) · 15 critical · 17 moderate
          analysis_id 7f3c9a2e-4b1d-…

You: Is it safe to close SSH on NAME_132?

Emfirge → modeled result: removes 1 critical + resolves 1 toxic combo · 0 new findings`,
          },
        ]}
      />

      <H2>Why it&apos;s not a scanner</H2>
      <P>
        Most cloud-security tools scan your account and hand you a list of problems with a fix to
        &quot;just trust.&quot; That&apos;s the crowded part of the market, and it&apos;s not us.
        Emfirge is the step that comes <Strong>before you apply a change</Strong>: it rehearses the
        change on a copy of your cloud and <Strong>shows the modeled result</Strong>, so you (or your AI)
        aren&apos;t guessing. Scanners tell you what&apos;s wrong. Emfirge tells you what the modeled security delta looks like,
        without writing to prod.
      </P>

      <Callout type="note" title="Deterministic by design">
        No AI runs inside the scoring. The same setup always produces the same score and the same
        result, so you can trust the numbers. Your assistant is the only AI in the loop, and in{" "}
        <Code>strict</Code> mode your resource names are swapped for tokens like <Code>NAME_###</Code>{" "}
        before it ever sees them.
      </Callout>

      <H2>One graph, many answers</H2>
      <P>
        Because Emfirge maps your cloud into a single <Strong>connected graph</Strong> (not a
        checklist of settings), that one map answers far more than &quot;what&apos;s
        misconfigured.&quot; The same graph shows you:
      </P>
      <ul className="mt-5 list-disc space-y-2 pl-4 text-[14.5px] leading-[1.75] text-prose">
        <li>
          <Strong>Attack paths</Strong>: the routes someone could take from the internet to your
          data, ranked by how hard each step is.
        </li>
        <li>
          <Strong>Blast radius</Strong>: if one resource is compromised, everything it could reach
          next.
        </li>
        <li>
          <Strong>Toxic combinations</Strong>: settings that are fine on their own but dangerous
          together.
        </li>
        <li>
          <Strong>Chokepoints</Strong>: the few resources that sit on the most paths, so you know
          what to fix first.
        </li>
      </ul>
      <P>
        These aren&apos;t separate products to buy. They fall out of the{" "}
        <Strong>same graph you already mapped</Strong>, and they feed the same fork when you test a
        change. Map your cloud once, and your assistant can explore all of it.
      </P>

      <H2>What you can do</H2>
      <P>Everything your assistant can do maps to a focused set of tools:</P>
      <CardGrid>
        <Card href="/docs/tools/scan" title="emfirge_scan">Scan an account → risk score + analysis_id.</Card>
        <Card href="/docs/tools/get-findings" title="emfirge_get_findings">Full findings, filterable by severity.</Card>
        <Card href="/docs/tools/attack-paths" title="emfirge_attack_paths">Internet-to-data paths + chokepoints.</Card>
        <Card href="/docs/tools/verify-fix" title="emfirge_verify_fix">Fork the graph, model a fix, read the delta.</Card>
        <Card href="/docs/tools/simulate-breach" title="emfirge_simulate_breach">Walk a full kill chain from a what-if.</Card>
        <Card href="/docs/tools/check-compliance" title="emfirge_check_compliance">CIS 1.5 / SOC 2 per-control status.</Card>
        <Card href="/docs/tools/setup-help" title="emfirge_setup_help">One-click CloudFormation URL for the read-only role.</Card>
      </CardGrid>

      <H2>Where we are today</H2>
      <P>
        Emfirge is early and we&apos;re building in the open. We&apos;d rather be upfront about the
        edges than over-promise, so here&apos;s the honest state of things:
      </P>
      <Callout type="warning" title="Honest limits (for now)">
        <ul className="mt-1 list-disc space-y-1.5 pl-4">
          <li>
            We show whether a modeled change adds <Strong>new security risk</Strong>. We don&apos;t yet check that
            it won&apos;t break app connectivity. &quot;Security result&quot; means &quot;no modeled security regression,&quot; not &quot;won&apos;t break anything.&quot;
          </li>
          <li>
            The copy is built from your <Strong>most recent scan</Strong>, so keep scans fresh. A
            stale copy reflects a cloud that may have changed.
          </li>
          <li>
            The deepest modeled verification path is strongest on our <Strong>core fixes</Strong> today;
            we&apos;re actively expanding coverage.
          </li>
        </ul>
      </Callout>

      <H2>Next steps</H2>
      <P>
        Install in 30 seconds and run your first scan in the <A href="/docs/quickstart">Quickstart</A>,
        or read <A href="/docs/how-it-works">How the fork works</A> to understand the engine. Scans
        are subject to operational limits; no signup or API keys are required.
      </P>

      <PrevNext prev={prev} next={next} />
      </>
    </DocsLayout>
  );
}
