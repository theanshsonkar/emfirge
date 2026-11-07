"use client";

import { useEffect, useState } from "react";
import type { TLine } from "@/content";
import { cn } from "@/lib/cn";
import { useReduced } from "@/lib/useReduced";

const TYPED = new Set(["prompt", "user", "cmd"]);
const INDENT: Record<string, number> = { prompt: 0, user: 0, agent: 0, cmd: 2, out: 4, fail: 4, blank: 0 };

function Tone({ text }: { text: string }) {
  const m = text.match(/\b(block|pass)\b/);
  if (!m || m.index === undefined) return <>{text}</>;
  return (
    <>
      {text.slice(0, m.index)}
      <span className={cn("font-medium", m[1] === "block" ? "text-block" : "text-pass")}>{m[1]}</span>
      {text.slice(m.index + m[1].length)}
    </>
  );
}

function Glyph({ k }: { k: string }) {
  if (k === "user") return <span className="text-ink-3">&gt;</span>;
  if (k === "agent") return <span>●</span>;
  if (k === "cmd") return <span className="text-ink-3">$</span>;
  if (k === "fail") return <span className="text-block">✗</span>;
  return null;
}

/**
 * Light macOS Terminal body. With `animate` it plays once (typing ~25ms/char, then lines
 * appear); otherwise, and for reduced motion / no JS, it shows the final state.
 * All lines are always laid out (hidden until revealed) so the window never changes height.
 */
export function TerminalScript({
  lines,
  animate = false,
  className,
}: {
  lines: TLine[];
  animate?: boolean;
  className?: string;
}) {
  const reduced = useReduced();
  const total = lines.length;
  const [p, setP] = useState({ line: total, chars: 0 });

  useEffect(() => {
    if (!animate || reduced) {
      setP({ line: total, chars: 0 });
      return;
    }
    let dead = false;
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
    (async () => {
      setP({ line: 0, chars: 0 });
      await sleep(450);
      for (let i = 0; i < total; i++) {
        const l = lines[i];
        if (TYPED.has(l.k)) {
          for (let c = 1; c <= l.t.length; c++) {
            if (dead) return;
            setP({ line: i, chars: c });
            await sleep(25);
          }
          await sleep(l.k === "cmd" ? 380 : 520);
        } else {
          if (dead) return;
          setP({ line: i, chars: l.t.length });
          await sleep(l.k === "blank" ? 120 : l.k === "agent" ? 640 : 340);
        }
      }
      if (!dead) setP({ line: total, chars: 0 });
    })();
    return () => {
      dead = true;
    };
  }, [animate, reduced, lines, total]);

  const playing = animate && p.line < total;

  return (
    <div
      className={cn(
        "bg-surface px-3.5 py-3 font-mono text-[12px] leading-[19px] text-ink sm:px-4 sm:text-[13px] sm:leading-5",
        className,
      )}
      role="img"
      aria-label={lines.map((l) => l.t).join(". ")}
    >
      <div aria-hidden="true">
        {lines.map((l, i) => {
          const done = i < p.line;
          const current = i === p.line;
          const shownChars = done ? l.t.length : current ? p.chars : 0;
          const visible = done || (current && p.chars > 0);
          if (l.k === "blank") return <div key={i} className="h-[19px] sm:h-5" />;
          const full = shownChars >= l.t.length;
          const typed = l.t.slice(0, shownChars);
          const rest = l.t.slice(shownChars);
          return (
            <div
              key={i}
              className={cn("flex", !visible && "invisible", l.k === "out" || l.k === "fail" ? "text-ink-2" : "")}
              style={{ paddingLeft: `${INDENT[l.k]}ch` }}
            >
              {l.k !== "prompt" && l.k !== "out" && (
                <span className="w-[2ch] shrink-0">
                  <Glyph k={l.k} />
                </span>
              )}
              <span className="min-w-0 whitespace-pre-wrap break-words">
                {full && l.k === "out" ? <Tone text={l.t} /> : typed}
                {playing && current && (
                  <span className="inline-block w-0 overflow-visible whitespace-nowrap">
                    <span className="cursor inline-block h-[15px] w-[7px] align-[-3px] bg-ink/80" />
                  </span>
                )}
                <span className="invisible">{full && l.k === "out" ? "" : rest}</span>
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
