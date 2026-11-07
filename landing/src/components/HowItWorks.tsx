"use client";

import { useReduced } from "@/lib/useReduced";
import { useRef, useState } from "react";
import { AnimatePresence, motion, useMotionValueEvent, useScroll, useTransform } from "motion/react";
import { Container } from "./ui/Container";
import { Eyebrow, H2 } from "./ui/Section";
import { Rich } from "./ui/Rich";
import { Frame } from "./ui/Frame";
import { cn } from "@/lib/cn";
import { HOW, VERBS, type TermLine, type Tone } from "@/content";

const TONE: Record<Tone, string> = {
  paper: "text-paper",
  muted: "text-muted",
  forge: "text-forge",
  pass: "text-pass",
  block: "text-block",
};

function Lines({ lines }: { lines: TermLine[] }) {
  return (
    <>
      {lines.map((l, i) => (
        <p key={i} className="whitespace-pre-wrap break-words">
          {l.segs.map((s, j) => (
            <span key={j} className={cn(TONE[s.tone ?? "paper"], s.bold && "font-bold")}>{s.text}</span>
          ))}
        </p>
      ))}
    </>
  );
}

function VerbTerminal({ i, className }: { i: number; className?: string }) {
  const v = VERBS[i];
  return (
    <div className={cn("font-mono text-[12.5px] leading-[1.7] sm:text-[13.5px]", className)}>
      <p className="break-words">
        <span className="text-muted">$ emfirge </span>
        <span className="text-forge">{v.example.replace("emfirge ", "").split(" ")[0]}</span>
        <span className="text-paper"> {v.example.replace("emfirge ", "").split(" ").slice(1).join(" ")}</span>
      </p>
      <div className="mt-2">
        <Lines lines={v.output} />
      </div>
    </div>
  );
}

function LoopRing({ progress }: { progress: ReturnType<typeof useScroll>["scrollYProgress"] }) {
  const reduce = useReduced();
  const len = useTransform(progress, [0.02, 0.98], [0, 1]);
  const pts = [
    { x: 60, y: 8, l: HOW.loop[0], a: "middle" as const, dy: -10 },
    { x: 112, y: 60, l: HOW.loop[1], a: "start" as const, dy: 4 },
    { x: 60, y: 112, l: HOW.loop[2], a: "middle" as const, dy: 22 },
    { x: 8, y: 60, l: HOW.loop[3], a: "end" as const, dy: 4 },
  ];
  return (
    <svg viewBox="-34 -22 228 168" className="h-auto w-full max-w-[236px]" aria-hidden="true">
      <circle cx="60" cy="60" r="52" fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth="2" />
      <motion.circle
        cx="60"
        cy="60"
        r="52"
        fill="none"
        stroke="#FF5A1F"
        strokeWidth="2.5"
        strokeLinecap="round"
        transform="rotate(-90 60 60)"
        style={{ pathLength: reduce ? 1 : len }}
      />
      {pts.map((p) => (
        <g key={p.l}>
          <circle cx={p.x} cy={p.y} r="4.5" fill="#0b0b0c" stroke="#FF5A1F" strokeWidth="1.8" />
          <text
            x={p.a === "middle" ? p.x : p.a === "start" ? p.x + 12 : p.x - 12}
            y={p.y + p.dy}
            textAnchor={p.a}
            fontSize="11"
            fill="#EDEBE6"
            fontFamily="var(--font-jetbrains), monospace"
          >
            {p.l}
          </text>
        </g>
      ))}
      <text x="60" y="64" textAnchor="middle" fontSize="22" fill="#FF5A1F">↺</text>
    </svg>
  );
}

export function HowItWorks() {
  const ref = useRef<HTMLDivElement>(null);
  const reduce = useReduced();
  const [active, setActive] = useState(0);
  const { scrollYProgress } = useScroll({ target: ref, offset: ["start start", "end end"] });
  useMotionValueEvent(scrollYProgress, "change", (p) => {
    setActive(Math.max(0, Math.min(VERBS.length - 1, Math.floor(p * VERBS.length))));
  });

  const heading = (
    <>
      <Eyebrow>{HOW.eyebrow}</Eyebrow>
      <H2 id="how-h" className="max-w-[16ch]">
        <Rich text={HOW.h2} />
      </H2>
    </>
  );

  return (
    <section id="how-it-works" aria-labelledby="how-h" className="relative">
      {/* Desktop: sticky, scroll-driven */}
      <div ref={ref} className={cn("relative hidden h-[330vh]", !reduce && "lg:block")}>
        <div className="sticky top-0 flex h-screen items-center">
          <Container className="grid grid-cols-[1fr_1.05fr] items-center gap-16 pt-16">
            <div>
              {heading}
              <ol className="mt-8 space-y-1">
                {VERBS.map((v, i) => (
                  <li
                    key={v.name}
                    className={cn(
                      "relative rounded-xl py-2.5 pl-6 pr-3 transition-opacity duration-300",
                      i === active ? "opacity-100" : "opacity-45",
                    )}
                  >
                    <span
                      aria-hidden="true"
                      className={cn(
                        "absolute bottom-2 left-0 top-2 w-[3px] rounded-full transition-colors duration-300",
                        i === active ? "bg-forge shadow-[0_0_14px_rgba(255,90,31,0.8)]" : "bg-white/10",
                      )}
                    />
                    <div className="flex items-baseline gap-3">
                      <span className="font-mono text-xs text-muted">{String(i + 1).padStart(2, "0")}</span>
                      <span className={cn("font-mono text-lg font-medium", i === active ? "text-forge" : "text-paper")}>{v.name}</span>
                      <span className="min-w-0 text-[14.5px] leading-snug text-muted">{v.line}</span>
                    </div>
                  </li>
                ))}
              </ol>
              <div className="mt-6 flex items-center gap-6">
                <LoopRing progress={scrollYProgress} />
                <p className="max-w-[30ch] text-[15px] leading-relaxed text-muted">{HOW.footer}</p>
              </div>
            </div>

            <div className="relative">
              <div
                aria-hidden="true"
                className="absolute -inset-10 bg-[radial-gradient(closest-side,rgba(255,90,31,0.22),transparent),radial-gradient(closest-side_at_80%_90%,rgba(90,40,110,0.4),transparent)] blur-2xl"
              />
              <Frame radius={20} tone="forge" innerClassName="bg-[#0c0c0e]">
                <div className="flex h-11 items-center gap-2 border-b border-white/[0.07] px-4">
                  <span className="size-2.5 rounded-full bg-white/15" />
                  <span className="size-2.5 rounded-full bg-white/15" />
                  <span className="size-2.5 rounded-full bg-white/15" />
                  <span className="ml-3 font-mono text-[11px] text-muted">~/infra — claude</span>
                </div>
                <div className="relative h-[250px] px-6 py-6">
                  <AnimatePresence mode="wait" initial={false}>
                    <motion.div
                      key={active}
                      initial={reduce ? false : { opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -8 }}
                      transition={{ duration: 0.22 }}
                    >
                      <VerbTerminal i={active} />
                    </motion.div>
                  </AnimatePresence>
                </div>
              </Frame>
            </div>
          </Container>
        </div>
      </div>

      {/* Mobile / tablet: stacked cards */}
      <div className={cn("py-20", !reduce && "lg:hidden")}>
        <Container>
          {heading}
          <ol className="mt-10 space-y-4">
            {VERBS.map((v, i) => (
              <li key={v.name}>
                <Frame radius={18} innerClassName="bg-[#0f0f11] p-5">
                  <div className="flex items-baseline gap-3">
                    <span className="font-mono text-xs text-muted">{String(i + 1).padStart(2, "0")}</span>
                    <span className="font-mono text-lg font-medium text-forge">{v.name}</span>
                  </div>
                  <p className="mt-2 text-[14.5px] leading-snug text-muted">{v.line}</p>
                  <VerbTerminal i={i} className="mt-4 rounded-xl border border-white/[0.08] bg-black/40 p-3.5" />
                </Frame>
              </li>
            ))}
          </ol>
          <p className="mt-10 max-w-[52ch] text-base leading-relaxed text-muted">{HOW.footer}</p>
        </Container>
      </div>
    </section>
  );
}
