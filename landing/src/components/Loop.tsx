"use client";

import { motion, useReducedMotion } from "motion/react";
import { ArrowUp, ChevronRight, RotateCcw } from "lucide-react";
import { Section, H2, Eyebrow } from "./ui/Section";
import { cn } from "@/lib/cn";
import { LOOP_STEPS } from "@/content";

function RetryArc() {
  const reduce = useReducedMotion();
  return (
    <div className="relative mt-1 hidden grid-cols-8 gap-4 md:grid" aria-hidden="true">
      <div className="relative col-span-3 col-start-3">
        <svg viewBox="0 0 500 56" preserveAspectRatio="none" className="h-14 w-full overflow-visible">
          <motion.path
            d="M417 0 V30 Q417 50 397 50 H103 Q83 50 83 30 V6"
            fill="none"
            className="stroke-forge"
            strokeWidth={2}
            strokeLinecap="round"
            vectorEffect="non-scaling-stroke"
            initial={reduce ? false : { pathLength: 0 }}
            whileInView={{ pathLength: 1 }}
            viewport={{ once: true, margin: "0px 0px -80px 0px" }}
            transition={{ duration: 1.2, ease: "easeInOut" }}
          />
        </svg>
        <ArrowUp size={16} strokeWidth={2.5} className="absolute -top-0.5 left-[16.6%] -translate-x-1/2 text-forge" />
        <p className="absolute inset-x-0 top-[34px] text-center font-mono text-xs text-forge">
          <span className="bg-ink px-2">↺ agent fixes and retries</span>
        </p>
      </div>
    </div>
  );
}

export function Loop() {
  return (
    <Section id="how-it-works" aria-labelledby="loop-h">
      <Eyebrow>How it works</Eyebrow>
      <H2 id="loop-h">The loop is the product.</H2>

      {/* Desktop: horizontal */}
      <div className="mt-14 hidden md:block">
        <ol className="grid grid-cols-8 gap-4">
          {LOOP_STEPS.map((s, i) => (
            <li
              key={s.name}
              className={cn(
                "relative rounded-xl border bg-surface px-2 py-4 text-center",
                s.inRetry ? "border-forge/50" : "border-line",
              )}
            >
              <span className="block font-mono text-[11px] text-muted">{String(i + 1).padStart(2, "0")}</span>
              <span className="mt-1 block font-mono text-[13px] text-paper">{s.name}</span>
              {i < LOOP_STEPS.length - 1 && (
                <ChevronRight size={14} aria-hidden="true" className="absolute -right-[15px] top-1/2 -translate-y-1/2 text-muted" />
              )}
            </li>
          ))}
        </ol>
        <RetryArc />
      </div>

      {/* Mobile: vertical */}
      <ol className="mt-10 md:hidden">
        {LOOP_STEPS.map((s, i) => (
          <li key={s.name} className="relative pb-3 pl-12">
            <span
              className={cn(
                "absolute left-0 top-0 flex size-8 items-center justify-center rounded-full border bg-surface font-mono text-[11px] text-muted",
                s.inRetry ? "border-forge/60" : "border-line",
              )}
            >
              {String(i + 1).padStart(2, "0")}
            </span>
            {i < LOOP_STEPS.length - 1 && <span aria-hidden="true" className="absolute bottom-0 left-4 top-8 w-px bg-line" />}
            <div className={cn("rounded-xl border bg-surface px-4 py-2.5 font-mono text-sm", s.inRetry ? "border-forge/50" : "border-line")}>
              {s.name}
            </div>
            {s.name === "signals" && (
              <div className="mt-3 flex items-center gap-2 rounded-xl border border-dashed border-forge px-4 py-2.5 font-mono text-xs text-forge">
                <RotateCcw size={14} aria-hidden="true" /> agent fixes and retries, back to try
              </div>
            )}
          </li>
        ))}
      </ol>

      <p className="mt-12 max-w-[62ch] text-lg leading-relaxed text-muted">
        Your agent fails on a branch, reads the signal, fixes its own plan and tries again, like reading a failed
        test. Only what&apos;s left reaches you.
      </p>
    </Section>
  );
}
