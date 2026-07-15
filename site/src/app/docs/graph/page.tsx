import { A, DocHeader, Lead, H2, H3, P, Strong, Code, Callout, PrevNext } from "@/components/docs/ui";
import { CodeBlock } from "@/components/docs/code-block";
import { prevNext } from "@/lib/nav";

export const metadata = {
  title: "One graph, many answers · Emfirge Docs",
  description:
    "How Emfirge models your cloud as a single typed graph, how it grows with your account, and everything derived from it: attack paths, blast radius, chokepoints, toxic combinations, rules, and their honest limits.",
};

// Exploit-difficulty weights, mirrored from the backend EDGE_WEIGHTS map.
const WEIGHTS = [
  { w: 0, meaning: "Structural, not an exploit step", ex: "instance ↔ security group, subnet / VPC containment, Lambda → VPC" },
  { w: 1, meaning: "Trivial, automated scanners", ex: "Internet → security group, Internet → instance, CloudFront → S3 origin" },
  { w: 2, meaning: "Needs a step (bypass or a valid call)", ex: "load balancer → instance, role → data store, Lambda → secret" },
  { w: 3, meaning: "Needs a shell plus credential theft", ex: "instance → IAM role, ECS task → IAM role" },
];

const COMBOS = [
  { id: "SSH_OPEN_NO_GUARDDUTY", desc: "SSH open to the world with no GuardDuty watching for the intrusion." },
  { id: "PUBLIC_RDS_NO_CLOUDTRAIL", desc: "Internet-reachable RDS with no CloudTrail to record who touched it." },
  { id: "PUBLIC_S3_NO_CLOUDTRAIL", desc: "Public S3 bucket with no audit trail on access." },
  { id: "ROOT_KEYS_ACTIVE_AND_USED", desc: "Root account access keys that are both active and in use." },
  { id: "IAM_NO_MFA_OLD_KEYS", desc: "IAM user with no MFA and stale long-lived access keys." },
  { id: "LAMBDA_ADMIN_NO_CLOUDTRAIL", desc: "Lambda with an admin-level role and no CloudTrail." },
  { id: "RDS_NO_BACKUP_NO_DELETION_PROTECTION", desc: "RDS with backups off and deletion protection off." },
  { id: "PUBLIC_S3_UNENCRYPTED", desc: "Public S3 bucket that is also unencrypted at rest." },
  { id: "SSH_OPEN_SINGLE_EC2", desc: "SSH open to the internet on a lone EC2 with nothing in front of it." },
];

export default function Page() {
  const { prev, next } = prevNext("/docs/graph");
  return (
    <>
      <DocHeader eyebrow="Concepts" title="One graph, many answers">
        <Lead>
          Emfirge maps your cloud into a single connected graph, not a checklist of settings. That
          one map is the whole product: attack paths, blast radius, chokepoints, toxic combinations,
          and the fork are all just <Strong>queries over the same graph</Strong>. Map once, and your
          assistant can explore all of it.
        </Lead>
      </DocHeader>

      <H2>What the graph is</H2>
      <P>
        Every resource a scan finds becomes a <Strong>node</Strong>. Every real relationship between
        two resources becomes a <Strong>directed edge</Strong>. The public internet is a first-class
        node too, so &quot;reachable from the internet&quot; is a literal path in the graph rather
        than a guess. Today the engine models roughly <Strong>20 service types</Strong>:
      </P>
      <ul className="mt-5 grid grid-cols-2 gap-x-6 gap-y-2 pl-4 text-[14px] text-prose sm:grid-cols-3">
        {[
          "internet", "vpc", "subnet", "security_group", "ec2_instance", "load_balancer",
          "iam_role", "rds_instance", "s3_bucket", "lambda_function", "ecs_tasks", "api_gateway",
          "elasticache", "dynamodb_table", "cloudfront", "secrets_manager", "kms_key", "sqs_queue",
          "ebs_volume", "elastic_ip",
        ].map((t) => (
          <li key={t} className="list-disc">
            <Code>{t}</Code>
          </li>
        ))}
      </ul>
      <P>
        The edges are the interesting part. They encode what actually connects to what:{" "}
        <Code>REACHES</Code> (internet to a security group), <Code>uses_iam_role</Code> (an instance
        assuming a role), <Code>can_access</Code> (a role reaching a data store),{" "}
        <Code>REFERENCES_SECRET</Code>, subnet and VPC containment, and more. A finding is never a
        floating line item; it hangs off the nodes and edges that produced it.
      </P>

      <H2>Edges carry exploit difficulty</H2>
      <P>
        Not every hop is equally easy for an attacker, so every edge type carries a{" "}
        <Strong>weight from 0 to 3</Strong>. This is what lets Emfirge rank a route by how hard it
        actually is, instead of just counting hops.
      </P>
      <div className="mt-5 overflow-x-auto rounded-md border border-border">
        <table className="w-full border-collapse text-left text-[13px]">
          <thead>
            <tr className="border-b border-border bg-muted/50 text-[10.5px] uppercase tracking-[0.08em] text-muted-foreground">
              <th className="px-3.5 py-2.5 font-medium">Weight</th>
              <th className="px-3.5 py-2.5 font-medium">Meaning</th>
              <th className="px-3.5 py-2.5 font-medium">Example edges</th>
            </tr>
          </thead>
          <tbody>
            {WEIGHTS.map((r) => (
              <tr key={r.w} className="border-b border-border-soft align-top last:border-0">
                <td className="px-3.5 py-3">
                  <code className="font-mono text-[13px] font-medium text-foreground">{r.w}</code>
                </td>
                <td className="px-3.5 py-3 text-[13.5px] text-foreground">{r.meaning}</td>
                <td className="px-3.5 py-3 font-mono text-[12px] leading-relaxed text-muted-foreground">{r.ex}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <P>
        Because of these weights, a 5-hop route made of trivial steps can outrank a 2-hop route that
        needs a shell and stolen credentials. The graph ranks by <Strong>effort</Strong>, not
        distance.
      </P>

      <H2>How big can it get</H2>
      <P>
        The graph is exactly as large as your account. Every scanned resource is a node, and edges
        grow faster than nodes as those resources start referencing each other, so a few hundred
        resources can already produce thousands of edges and a much larger space of possible paths.
        The more you build, and the more services Emfirge covers, the denser the map and the more
        real attack routes and toxic combinations <Strong>emerge on their own</Strong>, without new
        rules.
      </P>
      <Callout type="note" title="Built to stay fast and honest">
        Analysis runs entirely in memory and is fully deterministic, the same graph always yields the
        same answer. Path-finding and blast radius are capped at <Code>5</Code> hops, which keeps
        large accounts tractable and filters out routes too long to be a realistic single-attacker
        chain.
      </Callout>

      <H2>Everything is a query on the one graph</H2>
      <P>
        None of the following are separate products or separate scans. They all fall out of the same
        map you already built.
      </P>

      <H3>Attack paths</H3>
      <P>
        A weighted shortest-path search runs outward from the internet node, using the
        exploit-difficulty weights above. The result is every route from public to your data,{" "}
        <Strong>ranked by effort</Strong>. This is what <A href="/docs/tools/attack-paths"><Code>emfirge_attack_paths</Code></A> returns.
      </P>

      <H3>Blast radius</H3>
      <P>
        Pick any node and Emfirge runs a directional, outbound-only search from it: <Strong>if this
        one resource is compromised, everything it could reach next</Strong>. It deliberately ignores
        inbound edges, so the number reflects what is at risk downstream, not what protects the
        resource.
      </P>

      <H3>Chokepoints</H3>
      <P>
        Betweenness centrality scores how often each node sits on the paths between other nodes. The
        high scorers are <Strong>chokepoints</Strong>: harden one and you sever the most attack paths
        at once. It is how Emfirge tells you what to fix first instead of handing you a flat list.
      </P>

      <H3>Toxic combinations</H3>
      <P>
        Some settings are fine alone but dangerous together. Emfirge checks{" "}
        <Strong>9 curated multi-signal patterns</Strong> against the graph:
      </P>
      <ul className="mt-4 space-y-2 pl-4 text-[14px] leading-[1.7] text-prose">
        {COMBOS.map((c) => (
          <li key={c.id} className="list-disc">
            <Code>{c.id}</Code> {c.desc}
          </li>
        ))}
      </ul>

      <H3>Rules and scoring</H3>
      <P>
        <Strong>58 deterministic rules</Strong> run across <Strong>17 service families</Strong> (EC2
        and security groups, S3, RDS, IAM, Lambda, KMS, VPC, CloudTrail, Config, CloudWatch,
        GuardDuty, Secrets Manager, SNS, WAF, ECS, cost, and orphaned resources). Severity is
        context-aware: an SSH port open behind an ALB is not scored like one open to the internet.
        Findings roll up into a single <Code>0-100</Code> posture score (higher is safer) across four
        dimensions, security, availability, cost, and disaster recovery. No LLM runs in the scoring.
      </P>

      <H3>Orphaned resources</H3>
      <P>
        Nodes that sit in the graph with no meaningful connections, an unattached EBS volume, an idle
        elastic IP, surface as orphans: usually cleanup and cost rather than risk, but part of the
        same single pass.
      </P>

      <H3>The fork</H3>
      <P>
        When you test a change, Emfirge clones this graph, mutates the copy, and re-runs everything
        above. Same graph, same rules, now applied to a hypothetical. See{" "}
        <A href="/docs/how-it-works">How the fork works</A>.
      </P>

      <H2>Honest limits</H2>
      <Callout type="warning" title="What the graph does not know">
        <ul className="mt-1 list-disc space-y-1.5 pl-4">
          <li>
            It is a <Strong>snapshot</Strong>, built from your last scan, not a live read of AWS. Re-scan
            after you change infrastructure.
          </li>
          <li>
            Coverage is roughly <Strong>20 service types</Strong>. Anything outside that is a blind
            spot: if it is not in the graph, it cannot appear in a path, a blast radius, or a
            chokepoint.
          </li>
          <li>
            Exploit-difficulty weights (<Code>0</Code> to <Code>3</Code>) are a <Strong>heuristic</Strong>,
            hand-assigned per edge type, not a measurement of real-world exploitability.
          </li>
          <li>
            Attack paths and blast radius are capped at <Code>5</Code> hops. Longer chains are
            intentionally truncated.
          </li>
          <li>
            Blast radius is a <Strong>reachability count</Strong>, it shows what is downstream, not
            proof an attacker can chain every step.
          </li>
          <li>
            Toxic combinations are a fixed set of <Strong>9 patterns</Strong> today, not exhaustive.
            No toxic combo does not mean no risk.
          </li>
          <li>
            Scores are normalized by account size so they are comparable over time, but comparisons
            between very different accounts are approximate.
          </li>
        </ul>
      </Callout>

      <PrevNext prev={prev} next={next} />
    </>
  );
}
