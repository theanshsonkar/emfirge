"use client";

import { useReduced } from "@/lib/useReduced";
import { motion } from "motion/react";
import { Logo } from "./Logo";
import { Container } from "./ui/Container";
import { Section } from "./ui/Section";
import { CommandBox } from "./ui/CommandBox";
import { ButtonLink } from "./ui/Button";
import { CANVAS_NODES, KIND, CONNECT_CMD, FOOTER_LINKS } from "@/content";

/** Decorative, slowly drifting canvas nodes. */
const DRIFT = [
  { id: "cdn", x: "6%", y: "14%", d: 0 },
  { id: "web-alb", x: "20%", y: "68%", d: 1.2 },
  { id: "api-1", x: "74%", y: "10%", d: 0.6 },
  { id: "orders-db", x: "84%", y: "62%", d: 1.8 },
  { id: "nightly-sync", x: "56%", y: "82%", d: 2.4 },
  { id: "assets", x: "36%", y: "6%", d: 3 },
] as const;

function DriftingNodes() {
  const reduce = useReduced();
  return (
    <div aria-hidden="true" className="pointer-events-none absolute inset-0 overflow-hidden">
      {DRIFT.map((n) => {
        const node = CANVAS_NODES.find((c) => c.id === n.id)!;
        const k = KIND[node.kind];
        const Icon = k.icon;
        return (
          <motion.div
            key={n.id}
            className="absolute hidden items-center gap-2 rounded-xl border px-2.5 py-2 opacity-[0.32] sm:flex md:opacity-45"
            style={{ left: n.x, top: n.y, borderColor: `${k.color}30`, background: `linear-gradient(135deg, ${k.color}14, #121214 70%)` }}
            animate={reduce ? undefined : { y: [0, -14, 0, 10, 0], x: [0, 8, 0, -8, 0] }}
            transition={{ duration: 16 + n.d * 2, repeat: Infinity, ease: "easeInOut", delay: -n.d * 3 }}
          >
            <span className="flex size-7 items-center justify-center rounded-md" style={{ background: `${k.color}22`, color: k.color }}>
              <Icon size={14} />
            </span>
            <span className="font-mono text-[11px] text-paper/80">{n.id}</span>
          </motion.div>
        );
      })}
    </div>
  );
}

export function FinalCta() {
  return (
    <>
      <Section aria-label="Get started" className="relative overflow-hidden" reveal={false}>
        <div
          aria-hidden="true"
          className="pointer-events-none absolute left-1/2 top-1/2 h-[520px] w-[1000px] -translate-x-1/2 -translate-y-1/2 bg-[radial-gradient(closest-side,rgba(255,90,31,0.26),rgba(42,22,48,0.5)_55%,transparent)] blur-2xl"
        />
        <DriftingNodes />
        <div className="relative flex flex-col items-center py-8 text-center md:py-16">
          <h2 className="max-w-[14ch] font-display text-[clamp(46px,7.4vw,96px)] leading-[0.98] tracking-[-0.02em] text-balance">
            Let your agents own the cloud. <em className="text-forge">Safely.</em>
          </h2>
          <div className="mt-10 flex w-full flex-col items-center gap-3 sm:w-auto sm:flex-row">
            <CommandBox command={CONNECT_CMD} className="sm:w-auto sm:min-w-[400px]" />
            <ButtonLink href="#get-started" className="w-full sm:w-auto">Get started</ButtonLink>
          </div>
        </div>
      </Section>
      <footer className="border-t border-white/[0.07] py-12">
        <Container className="flex flex-col gap-8 md:flex-row md:items-start md:justify-between">
          <div>
            <Logo />
            <p className="mt-3 text-sm text-muted">The harness for cloud agents.</p>
          </div>
          <nav aria-label="Footer">
            <ul className="flex flex-wrap gap-x-6 gap-y-3 text-sm text-muted">
              {FOOTER_LINKS.map((l) => (
                <li key={l.label}><a href={l.href} className="hover:text-paper">{l.label}</a></li>
              ))}
            </ul>
          </nav>
        </Container>
        <Container className="mt-8 text-sm text-muted">Built by Ansh Sonkar</Container>
      </footer>
    </>
  );
}
