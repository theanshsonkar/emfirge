"use client";

import { useEffect, useState } from "react";
import { FORK } from "@/content";
import { useReduced } from "@/lib/useReduced";

const H = 132;
const T = 30; // trunk y
const Y1 = 68;
const Y2 = 104;

function Fork({ w }: { w: number }) {
  const f = (n: number) => Math.round(w * n);
  const b1 = f(0.38);
  const e1 = f(0.64);
  const b2 = f(0.47);
  const e2 = f(0.8);
  const m = f(0.9);
  const dots = [0.06, 0.18, 0.3, 0.38, 0.47, 0.9];
  const p1 = `M${b1} ${T}C${b1 + 28} ${T} ${b1 + 14} ${Y1} ${b1 + 44} ${Y1}H${e1}`;
  const p2 = `M${b2} ${T}C${b2 + 28} ${T} ${b2 + 14} ${Y2} ${b2 + 44} ${Y2}H${e2}`;
  const pm = `M${e2} ${Y2}C${e2 + 36} ${Y2} ${m - 36} ${T} ${m} ${T}`;
  const id = `fork-${w}`;
  const label = w < 500 ? 10 : 11;

  return (
    <svg
      viewBox={`0 0 ${w} ${H}`}
      className="block w-full"
      aria-hidden="true"
      fill="none"
    >
      <defs>
        <mask id={`${id}-m1`} maskUnits="userSpaceOnUse" x="0" y="0" width={w} height={H}>
          <path d={p1} stroke="#fff" strokeWidth="5" pathLength={1} className="draw" style={{ "--t": "0.6s", "--d": "0.4s" } as React.CSSProperties} />
        </mask>
        <mask id={`${id}-m2`} maskUnits="userSpaceOnUse" x="0" y="0" width={w} height={H}>
          <path d={p2} stroke="#fff" strokeWidth="5" pathLength={1} className="draw" style={{ "--t": "1s", "--d": "0.4s" } as React.CSSProperties} />
        </mask>
      </defs>

      <path d={`M0 ${T}H${w}`} stroke="#2E5A4B" strokeWidth="1.5" pathLength={1} className="draw" style={{ "--t": "0s", "--d": "0.6s" } as React.CSSProperties} />
      {dots.map((d, i) => (
        <circle
          key={d}
          cx={f(d)}
          cy={T}
          r="3.5"
          fill="#0C2A22"
          stroke="#3FCF8E"
          strokeWidth="1.5"
          className="pop"
          style={{ "--t": `${(d * 0.6).toFixed(2)}s` } as React.CSSProperties}
          data-i={i}
        />
      ))}

      <path d={p1} stroke="#F27F7F" strokeWidth="1.5" strokeDasharray="5 5" mask={`url(#${id}-m1)`} />
      <path d={p2} stroke="#3FCF8E" strokeWidth="1.5" strokeDasharray="5 5" mask={`url(#${id}-m2)`} />
      <path d={pm} stroke="#3FCF8E" strokeWidth="1.5" pathLength={1} className="draw" style={{ "--t": "1.4s", "--d": "0.2s" } as React.CSSProperties} />

      <g fontFamily="var(--font-geist-mono), monospace" fontSize={label} fill="#8FA39B">
        <text x={10} y={T - 10} className="pop" style={{ "--t": "0s" } as React.CSSProperties}>
          {FORK.trunk}
        </text>
        <text x={b1 + 54} y={Y1 - 9} className="pop" style={{ "--t": "0.7s" } as React.CSSProperties}>
          {FORK.branch1}
        </text>
        <text x={b2 + 54} y={Y2 - 9} className="pop" style={{ "--t": "1.1s" } as React.CSSProperties}>
          {FORK.branch2}
        </text>
      </g>

      <g className="pop" style={{ "--t": "1s" } as React.CSSProperties}>
        <circle cx={e1} cy={Y1} r="8" fill="#D93F3F" />
        <path d={`M${e1 - 3} ${Y1 - 3}l6 6M${e1 + 3} ${Y1 - 3}l-6 6`} stroke="#fff" strokeWidth="1.8" strokeLinecap="round" />
      </g>
      <g className="pop" style={{ "--t": "1.4s" } as React.CSSProperties}>
        <circle cx={e2} cy={Y2} r="8" fill="#0A8754" />
        <path d={`M${e2 - 3.5} ${Y2 + 0.5}l2.5 2.5l4.5 -5.5`} stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      </g>
    </svg>
  );
}

/** Draws once (~1.6s). Server render and reduced motion show the final drawing. */
export function HeroFork() {
  const reduced = useReduced();
  const [play, setPlay] = useState(false);
  useEffect(() => {
    if (!reduced) setPlay(true);
  }, [reduced]);

  return (
    <div role="img" aria-label={FORK.alt} className={play && !reduced ? "fork-play" : undefined}>
      <div className="md:hidden">
        <Fork w={390} />
      </div>
      <div className="hidden md:block lg:hidden">
        <Fork w={760} />
      </div>
      <div className="hidden lg:block">
        <Fork w={1200} />
      </div>
    </div>
  );
}
