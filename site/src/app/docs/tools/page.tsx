import { DocHeader, Lead, H2, P, Strong, Code, Callout, PrevNext } from "@/components/docs/ui";
import { prevNext } from "@/lib/nav";
import Link from "next/link";

export const metadata = {
  title: "MCP Tools · Emfirge Docs",
  description: "The seven tools Emfirge exposes to your AI, their inputs, and what they return.",
};

const TOOLS = [
  { name: "emfirge_scan", href: "/docs/tools/scan", desc: "Scan an AWS account. Returns risk score, finding counts, and an analysis_id.", args: "role_arn, region" },
  { name: "emfirge_get_findings", href: "/docs/tools/get-findings", desc: "Full findings for a scan, filterable by severity.", args: "analysis_id, severity?" },
  { name: "emfirge_attack_paths", href: "/docs/tools/attack-paths", desc: "Internet-to-data attack paths, chokepoints, and orphaned resources.", args: "analysis_id" },
  { name: "emfirge_verify_fix", href: "/docs/tools/verify-fix", desc: "Fork the graph, apply a fix, re-run rules, return the risk delta.", args: "rule_id, resource_id, analysis_id" },
  { name: "emfirge_simulate_breach", href: "/docs/tools/simulate-breach", desc: "Walk a full kill chain from a natural-language what-if.", args: "query, analysis_id" },
  { name: "emfirge_check_compliance", href: "/docs/tools/check-compliance", desc: "CIS AWS 1.5 / SOC 2 per-control pass/fail.", args: "analysis_id, framework?" },
  { name: "emfirge_setup_help", href: "/docs/tools/setup-help", desc: "Returns a one-click CloudFormation deploy URL for the read-only role.", args: "none" },
];

export default function Page() {
  const { prev, next } = prevNext("/docs/tools");
  return (
    <>
      <DocHeader eyebrow="MCP Tools" title="Overview">
        <Lead>
          Emfirge exposes <Strong>seven tools</Strong> over the Model Context Protocol. Your assistant
          decides which to call from your natural-language request, you rarely name them directly.
          All are deterministic on the backend and read-only against AWS.
        </Lead>
      </DocHeader>

      <H2>The tools</H2>
      <div className="mt-6 overflow-hidden rounded-xl border border-border">
        {TOOLS.map((t, i) => (
          <Link
            key={t.name}
            href={t.href}
            className={`block px-4 py-4 transition-colors hover:bg-accent/50 ${i !== 0 ? "border-t border-border-soft" : ""}`}
          >
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <code className="font-mono text-[13.5px] font-medium text-foreground">{t.name}</code>
              <code className="font-mono text-[11.5px] text-muted-foreground">({t.args})</code>
            </div>
            <p className="mt-1.5 text-[13.5px] leading-relaxed text-muted-foreground">{t.desc}</p>
          </Link>
        ))}
      </div>

      <H2>The typical flow</H2>
      <P>
        Almost every session starts with <Code>emfirge_scan</Code>, which returns an{" "}
        <Code>analysis_id</Code>. Every other tool (except <Code>setup_help</Code>) takes that
        <Code>analysis_id</Code> to operate on the same scanned graph, so findings, attack paths,
        fix-verification, and compliance all describe one consistent snapshot.
      </P>

      <Callout type="note" title="Tokens in, tokens out">
        Wherever a tool takes a <Code>resource_id</Code> (like <Code>verify_fix</Code>) or you
        reference a resource in a <Code>query</Code> (like <Code>simulate_breach</Code>), you can use
        the tokens from a previous response, <Code>NAME_132</Code>, <Code>NAME_133</Code>, and the MCP
        expands them to real IDs locally before the call.
      </Callout>

      <PrevNext prev={prev} next={next} />
    </>
  );
}
