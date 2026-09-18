import { A, DocHeader, Lead, H2, H3, P, Strong, Code, Callout, PrevNext } from "@/components/docs/ui";
import { CodeBlock } from "@/components/docs/code-block";
import { ForkFlow } from "@/components/docs/flow-diagram";
import { prevNext } from "@/lib/nav";

export const metadata = {
  title: "How the fork works · Emfirge Docs",
  description: "Read-only scan, modeled branch changes, diffs, and advisory verdicts.",
};

const LENSES = [
  {
    title: "Security",
    question: "Which native findings are new or removed by this AWS change?",
    mapping: "CombinedVerdict.native_added / CombinedVerdict.native_removed",
    bound: "58 native rule IDs across 17 native service families cover defined families, not every possible issue.",
    example: "Opening SSH to 0.0.0.0/0 adds an internet-reachable EC2 finding.",
  },
  {
    title: "Reachability",
    question: "What becomes reachable from the internet, or stops being reachable?",
    mapping: "CombinedVerdict.newly_internet_reachable / CombinedVerdict.no_longer_internet_reachable",
    bound: "This is modeled graph reachability, not a live connectivity probe.",
    example: "Attaching a public subnet path makes a modeled service newly internet-reachable.",
  },
  {
    title: "Blast radius",
    question: "What attack paths are reachable from a compromised node?",
    mapping: "CombinedVerdict has no standalone blast-radius or attack-path field; blast radius is represented by related finding and attack-path payloads exposed by the graph/findings analyses, not by a CombinedVerdict field. The combined branch verdict summarizes the resulting finding deltas but does not claim a top-level blast-radius mapping.",
    bound: "The result includes only modeled graph edges, known resources, and known paths.",
    example: "A compromised modeled role reaching a data store appears in its attack-path payload.",
  },
  {
    title: "IAM privilege escalation",
    question: "Does the modeled change introduce an IAM escalation path?",
    mapping: "CombinedVerdict.introduces_privilege_escalation. Policy/action metadata from policy_sentry informs upstream analysis; its annotations are not fields returned by CombinedVerdict.",
    bound: "This reflects IAM policy/action coverage and modeled principals, not proof of exploitability.",
    example: "Adding a modeled pass-role path marks privilege escalation as introduced.",
  },
  {
    title: "Cost",
    question: "What is the provisioned monthly cost delta for this change?",
    mapping: "CombinedVerdict.cost_delta_monthly_usd / CombinedVerdict.cost_unknown_notes",
    bound: "Usage-based costs remain unknown and labeled; Emfirge never fabricates them.",
    example: "Adding a provisioned resource produces a monthly delta while usage-based charges remain noted as unknown.",
  },
  {
    title: "Limits / capacity",
    question: "Which account or service limits does the change approach or breach?",
    mapping: "CombinedVerdict.limits_introduced / CombinedVerdict.limits_resolved",
    bound: "These are deterministic checks, not forecasting or a live quota guarantee.",
    example: "Adding resources beyond a modeled service limit adds a capacity finding.",
  },
];

export default function Page() {
  const { prev, next } = prevNext("/docs/how-it-works");
  return (
    <>
      <DocHeader eyebrow="Concepts" title="How the fork works">
        <Lead>
          Emfirge builds a graph from a read-only scan, lets you fork that snapshot, models a proposed
          change, and reports what the analysis says about the resulting branch.
        </Lead>
      </DocHeader>

      <H2>The graph</H2>
      <P>
        A scan reads the cloud through a read-only role and builds a connected infrastructure graph.
        The graph is the saved base for subsequent analysis; it is not a live write target and it
        becomes stale as the account changes.
      </P>

      <H2>The workflow</H2>
      <ForkFlow />
      <CodeBlock numbered tabs={[{ label: "flow", code: `read-only scan → fork graph → apply modeled branch change
→ diff the branch → re-run analysis lenses → advisory verdict` }]} />
      <P>
        Use <A href="/docs/tools/create-branch"><Code>emfirge_create_branch</Code></A> to fork a
        completed analysis. Add an <A href="/docs/tools/apply-change"><Code>emfirge_apply_change</Code></A>
        operation to the isolated model, then inspect <A href="/docs/tools/branch-diff"><Code>emfirge_branch_diff</Code></A>
        and <A href="/docs/tools/branch-verdict"><Code>emfirge_branch_verdict</Code></A>. The verdict
        combines modeled native findings with available scanner lenses and reports coverage explicitly.
      </P>

      <H2>What the branch measures</H2>
      <P>
        A branch verdict compares the modeled base and proposed branch across six lenses. Each lens
        answers a concrete AWS question, exposes its exact verdict fields, and states what the model
        cannot establish.
      </P>
      <div className="mt-5 space-y-5">
        {LENSES.map((lens) => (
          <div key={lens.title} className="rounded-md border border-border p-4">
            <H3>{lens.title}</H3>
            <dl className="mt-3 space-y-2 text-[14px] leading-[1.65]">
              <div><dt className="font-medium text-foreground">AWS question</dt><dd className="text-prose">{lens.question}</dd></div>
              <div><dt className="font-medium text-foreground">CombinedVerdict mapping</dt><dd className="text-prose"><Code>{lens.mapping}</Code></dd></div>
              <div><dt className="font-medium text-foreground">Honest bound</dt><dd className="text-prose">{lens.bound}</dd></div>
              <div><dt className="font-medium text-foreground">Example</dt><dd className="text-prose">{lens.example}</dd></div>
            </dl>
          </div>
        ))}
      </div>

      <H3>Borrowed scanners</H3>
      <P>
        Checkov, Trivy, and cloudsplaining run at arm&apos;s length against the branch when available;
        they do not become native rules. Their findings fold into <Code>scanner_added</Code> and
        <Code>scanner_removed</Code> alongside the same combined verdict. A missing executable or
        package, timeout, invalid or empty output, disabled scanner, or another unavailable state
        degrades honestly: <Code>scanner_status</Code> reports each state, and
        <Code>coverage_warnings</Code> says the result is <Strong>NOT full coverage</Strong>. Do not
        assume all scanners always run.
      </P>

      <H3>Combined verdict</H3>
      <P>
        <Code>block</Code>, <Code>warn</Code>, or <Code>pass</Code> combines native and scanner
        deltas, reachability, cost, privilege escalation, limits, and the human-readable
        <Code>summary</Code> into one advisory result. It proves the change against a model of the
        cloud, not the live cloud: it computes a security delta and never guarantees safety.
      </P>
      <Callout type="warning" title="Read coverage warnings">
        <Code>coverage_warnings</Code> is non-empty when lenses are missing or disabled. In that case
        the result is degraded: do not describe it as complete coverage or a guarantee of safety. A
        pass means no modeled concern was found by the available analysis, not that deployment is
        risk-free.
      </Callout>

      <H2>Honest limits</H2>
      <P>
        Branches are models, not deployments. Emfirge does not apply branch changes to AWS, and a
        security delta does not prove application connectivity or every operational consequence.
        Re-scan before relying on a result when the live environment has changed.
      </P>

      <PrevNext prev={prev} next={next} />
    </>
  );
}
