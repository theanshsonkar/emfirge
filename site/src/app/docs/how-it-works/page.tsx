import { A, DocHeader, Lead, H2, H3, P, Strong, Code, Callout, PrevNext } from "@/components/docs/ui";
import { CodeBlock } from "@/components/docs/code-block";
import { ForkFlow } from "@/components/docs/flow-diagram";
import { prevNext } from "@/lib/nav";

export const metadata = {
  title: "How the fork works · Emfirge Docs",
  description: "The clone → mutate → re-score → diff engine, the graph, the 58 rules, and its honest limits.",
};

export default function Page() {
  const { prev, next } = prevNext("/docs/how-it-works");
  return (
    <>
      <DocHeader eyebrow="Concepts" title="How the fork works">
        <Lead>
          Emfirge&apos;s one genuinely rare capability: it clones your infrastructure graph in memory,
          applies a proposed change, re-runs every rule, and diffs the result, so your AI reads back
          what the engine <Strong>proved</Strong>, not what it guessed.
        </Lead>
      </DocHeader>

      <H2>The graph</H2>
      <P>
        A scan doesn&apos;t just list resources, it builds a weighted graph of ~20 AWS services (EC2,
        security groups, S3, RDS, IAM, Lambda, ELB/ALB, CloudFront, VPC, KMS, and more) and the edges
        between them. That graph is what makes the rest possible: attack paths are routes through it,
        blast radius is transitive reach across it, and a fix is a mutation of it.
      </P>

      <H2>The four steps</H2>
      <ForkFlow />

      <CodeBlock
        numbered
        tabs={[
          {
            label: "verify_fix result",
            code: `{
  "can_simulate": true,
  "findings_removed": [ /* full finding objects */ ],
  "findings_added": [],
  "toxic_combos_resolved": ["SSH_OPEN_NO_GUARDDUTY"],
  "score_before": 3,
  "score_after": 3,
  "score_delta": 0,
  "safe_to_apply": true
}`,
          },
        ]}
        footer={<><span className="font-medium" style={{ color: "var(--safe)" }}>✓ proven</span><span>· re-scored on the clone, no AWS change.</span></>}
      />

      <H2>The rules</H2>
      <P>
        58 graph-aware rules across 17 categories, with <Strong>context-aware severity</Strong>: an
        SSH port open behind an ALB is not the same risk as one open to the internet, and the score
        reflects that. The engine also detects <Strong>toxic combinations</Strong>, dangerous pairs
        like a public RDS instance with no CloudTrail, that are fine individually but critical
        together. Scoring is fully deterministic; no LLM is involved.
      </P>

      <H3>Attack paths &amp; chokepoints</H3>
      <P>
        Paths from the internet to your data are ranked by <Strong>exploit difficulty</Strong> (0 =
        metadata, 3 = needs a shell), so a 5-hop trivial path can outrank a 2-hop one that needs
        credential theft. Betweenness centrality surfaces <Strong>chokepoints</Strong>, the single
        resources that, hardened, kill the most paths at once.
      </P>

      <H2>Honest limits</H2>
      <Callout type="warning" title="Read this before you trust a result">
        The fork is only as fresh as your last scan, it mutates the saved graph, not a live re-read
        of AWS. If you changed a security group after scanning, re-scan before you prove a fix.{" "}
        <Code>safe_to_apply</Code> means <Strong>no new security finding and no worse score</Strong>;
        it does not verify that the change won&apos;t break app connectivity. And deterministic
        fix-simulation currently covers a specific set of rules, see{" "}
        <A href="/docs/tools/verify-fix"><Code>emfirge_verify_fix</Code></A>.
      </Callout>

      <PrevNext prev={prev} next={next} />
    </>
  );
}
