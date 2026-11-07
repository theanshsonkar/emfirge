"use client";

import type { CSSProperties } from "react";
import { FORK } from "@/content";
import { cn } from "@/lib/cn";
import { useForkPlay } from "./HeroFork";

const W = 480;
const H = 500;
const X = 40; // trunk x
const L = 100; // branch lane x
const TOTAL = 1.4; // seconds to draw top to bottom

/** Seconds at which the drawing reaches height y. */
const at = (y: number) => (y / H) * TOTAL;
const dur = (y0: number, y1: number) =>
  ({ "--t": `${at(y0).toFixed(2)}s`, "--d": `${(at(y1) - at(y0)).toFixed(2)}s` }) as CSSProperties;
const pop = (y: number) => ({ "--t": `${at(y).toFixed(2)}s` }) as CSSProperties;

const GREEN = "#3FCF8E";
const RED = "#F27F7F";
const MIST = "#E8EFEC";
const MUTED = "#8FA39B";

const p1 = `M${X} 150C${X} 176 ${L} 164 ${L} 190V262`;
const p2 = `M${X} 300C${X} 326 ${L} 314 ${L} 340V410`;
const pm = `M${L} 410C${L} 436 ${X} 424 ${X} 450`;

/** Vertical git-log style fork, shown from lg. Draws once top to bottom (~1.6s). */
export function HeroGraph() {
  const play = useForkPlay();
  const dot = (cy: number, cx = X, stroke = GREEN) => (
    <circle cx={cx} cy={cy} r="5" fill="#0C2A22" stroke={stroke} strokeWidth="1.5" className="pop" style={pop(cy)} />
  );
  return (
    <div role="img" aria-label={FORK.alt2} className={cn("hidden lg:block", play && "fork-play")}>
      <svg viewBox={`0 0 ${W} ${H}`} className="block h-auto w-full max-w-[480px]" fill="none" aria-hidden="true">
        <path d={`M${X} 20V490`} stroke="#2E5A4B" strokeWidth="1.5" pathLength={1} className="draw" style={dur(20, 490)} />
        <path d={p1} stroke={RED} strokeWidth="1.5" pathLength={1} className="draw" style={dur(150, 262)} />
        <path d={p2} stroke={GREEN} strokeWidth="1.5" pathLength={1} className="draw" style={dur(300, 410)} />
        <path d={pm} stroke={GREEN} strokeWidth="1.5" pathLength={1} className="draw" style={dur(410, 450)} />

        {dot(30)}
        {dot(76)}
        {dot(118)}
        {dot(150)}
        {dot(300)}
        {dot(450)}
        {dot(214, L, MUTED)}
        {dot(366, L, MUTED)}

        <g className="pop" style={pop(262)}>
          <circle cx={L} cy={262} r="9" fill="#D93F3F" />
          <path d={`M${L - 3.5} ${258.5}l7 7M${L + 3.5} ${258.5}l-7 7`} stroke="#fff" strokeWidth="1.8" strokeLinecap="round" />
        </g>
        <g className="pop" style={pop(410)}>
          <circle cx={L} cy={410} r="9" fill="#0A8754" />
          <path d={`M${L - 4} ${410.5}l3 3l5.5 -6.5`} stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        </g>

        <g fontFamily="var(--font-geist-mono), monospace" fontSize="13">
          <text x={X + 22} y={34} fill={MIST} className="pop" style={pop(30)}>
            live<tspan fill={MUTED}> · {FORK.live}</tspan>
          </text>
          <text x={L + 24} y={194} fill={MUTED} className="pop" style={pop(190)}>
            {FORK.branch1}
          </text>
          <text x={L + 24} y={218} fill={MIST} className="pop" style={pop(214)}>
            {FORK.b1[0]}
          </text>
          <text x={L + 24} y={266} fill={RED} className="pop" style={pop(262)}>
            {FORK.b1[1]}
          </text>
          <text x={L + 24} y={344} fill={MUTED} className="pop" style={pop(340)}>
            {FORK.branch2}
          </text>
          <text x={L + 24} y={370} fill={MIST} className="pop" style={pop(366)}>
            {FORK.b2[0]}
          </text>
          <text x={L + 24} y={414} fill={GREEN} className="pop" style={pop(410)}>
            {FORK.b2[1]}
          </text>
          <text x={X + 22} y={454} fill={MIST} className="pop" style={pop(450)}>
            {FORK.applied}
          </text>
        </g>
      </svg>
    </div>
  );
}
