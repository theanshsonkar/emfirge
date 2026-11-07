"use client";

import { useEffect, useRef, useState } from "react";
import { SPLIT, type LogRow } from "@/content";
import { cn } from "@/lib/cn";
import { useReduced } from "@/lib/useReduced";

const pill: Record<LogRow["signal"], string> = {
  block: "bg-block-on-dark/15 text-block-on-dark",
  pass: "bg-pass-on-dark/15 text-pass-on-dark",
};

/** Rows appear one by one (60ms stagger), once, when scrolled into view. Visible without JS. */
export function ConsoleLog() {
  const reduced = useReduced();
  const ref = useRef<HTMLOListElement>(null);
  const [armed, setArmed] = useState(false);
  const [shown, setShown] = useState(false);

  useEffect(() => {
    if (reduced || !ref.current) return;
    const el = ref.current;
    const io = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setShown(true);
          io.disconnect();
        }
      },
      { threshold: 0.3 },
    );
    setArmed(true);
    io.observe(el);
    return () => io.disconnect();
  }, [reduced]);

  const hidden = armed && !shown && !reduced;

  return (
    <ol ref={ref} className="divide-y divide-forest-line font-mono text-[13px] leading-5">
      {SPLIT.branch.rows.map((r, i) => (
        <li
          key={r.time + r.area}
          style={{ transitionDelay: shown ? `${i * 60}ms` : "0ms" }}
          className={cn(
            "grid grid-cols-[auto_auto_1fr] items-baseline gap-x-3 gap-y-1 px-4 py-3 transition duration-300 max-sm:grid-cols-[auto_1fr]",
            hidden && "translate-y-1 opacity-0",
          )}
        >
          <time className="text-mist-2">{r.time}</time>
          <span className={cn("w-fit rounded-full px-2 py-0.5 text-xs font-medium", pill[r.signal])}>
            {SPLIT.branch.pills[r.signal]}
          </span>
          <span className="text-mist max-sm:col-span-2">
            <span className="text-mist-2">{r.area}</span>
            <span className="text-mist-2">{"  "}</span>
            {r.text}
          </span>
        </li>
      ))}
    </ol>
  );
}
