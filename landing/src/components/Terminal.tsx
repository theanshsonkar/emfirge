"use client";

import { useEffect, useState } from "react";
import { motion, useReducedMotion } from "motion/react";
import { cn } from "@/lib/cn";
import { TERMINAL_SCRIPT, TERMINAL_TITLE, type Tone, type TermLine } from "@/content";

const TONE: Record<Tone, string> = {
  paper: "text-paper",
  muted: "text-muted",
  forge: "text-forge",
  pass: "text-pass",
  block: "text-block",
};
const STEP_MS = 520;

export function Terminal({
  script = TERMINAL_SCRIPT,
  title = TERMINAL_TITLE,
}: {
  script?: TermLine[];
  title?: string;
}) {
  const reduce = useReducedMotion();
  // Start fully shown: no-JS and reduced-motion users get the final state.
  const [shown, setShown] = useState(script.length);

  useEffect(() => {
    if (reduce) {
      setShown(script.length);
      return;
    }
    let n = 0;
    setShown(0);
    const id = setInterval(() => {
      n += 1;
      setShown(n);
      if (n >= script.length) clearInterval(id);
    }, STEP_MS);
    return () => clearInterval(id);
  }, [reduce, script.length]);

  return (
    <div className="relative">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -inset-x-6 -inset-y-10 bg-[radial-gradient(closest-side,rgba(255,90,31,0.28),transparent)] opacity-80"
      />
      <div className="relative overflow-hidden rounded-[14px] border border-line bg-surface shadow-2xl shadow-black/60">
        <div className="flex items-center gap-2 border-b border-line px-4 py-3">
          <span className="size-3 rounded-full bg-line" />
          <span className="size-3 rounded-full bg-line" />
          <span className="size-3 rounded-full bg-line" />
          <span className="ml-3 truncate font-mono text-xs text-muted">{title}</span>
        </div>
        {/* All lines are always laid out (hidden until typed), so the height is reserved. */}
        <div
          role="img"
          aria-label="Example terminal session: an agent is blocked from deleting orders-db, retries with legacy-reports-db only, and passes."
          className="space-y-0.5 px-4 py-5 font-mono text-[12px] leading-[1.6] sm:px-6 sm:text-[13.5px]"
        >
          {script.map((l, i) => (
            <motion.div
              key={i}
              aria-hidden="true"
              initial={false}
              animate={{ opacity: i < shown ? 1 : 0, y: i < shown ? 0 : 4 }}
              transition={{ duration: reduce ? 0 : 0.18 }}
              className={cn("flex gap-3", l.segs.length === 0 && "h-3")}
            >
              <span className="w-[7.5ch] shrink-0 whitespace-nowrap text-muted sm:w-[8ch]">{l.who ? `${l.who} ›` : ""}</span>
              <span className="min-w-0 whitespace-pre-wrap break-words">
                {l.segs.map((s, j) => (
                  <span key={j} className={cn(TONE[s.tone ?? "paper"], s.bold && "font-bold")}>{s.text}</span>
                ))}
              </span>
            </motion.div>
          ))}
        </div>
      </div>
    </div>
  );
}
