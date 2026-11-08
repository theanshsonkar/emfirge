"use client";
import { useEffect, useState } from "react";
import { useLive } from "./useLive";

// CLI figure: the six verbs on a ring. The verb for the section being read is highlighted (Shell's scroll-spy sends `emfirge:spy`).
const VERBS = [
  { id: "context", gloss: "what is true" },
  { id: "branch", gloss: "a copy to work on" },
  { id: "try", gloss: "put a change on it" },
  { id: "check", gloss: "six facts back" },
  { id: "request", gloss: "ask the owner (not built yet)" },
  { id: "report", gloss: "the hand-back" },
];
const CX = 320, CY = 108, RX = 236, RY = 66;
const pos = (i: number): [number, number] => { const a = ((180 + 60 * i) * Math.PI) / 180; return [CX + RX * Math.cos(a), CY + RY * Math.sin(a)]; };
const RING = `M ${CX - RX} ${CY} A ${RX} ${RY} 0 1 1 ${CX + RX} ${CY} A ${RX} ${RY} 0 1 1 ${CX - RX} ${CY}`;

export function VerbMap() {
  const { ref, live, still } = useLive<SVGSVGElement>();
  const [on, setOn] = useState<string | null>(null);
  useEffect(() => {
    const w = window as unknown as { __spy?: string };
    setOn(w.__spy ?? null);
    const h = (e: Event) => setOn((e as CustomEvent<string>).detail);
    window.addEventListener("emfirge:spy", h);
    return () => window.removeEventListener("emfirge:spy", h);
  }, []);
  useEffect(() => {
    const s = ref.current as unknown as SVGSVGElement & { pauseAnimations?: () => void; unpauseAnimations?: () => void };
    if (!s?.pauseAnimations) return;
    if (live && !still) s.unpauseAnimations?.(); else s.pauseAnimations?.();
  }, [live, still, ref]);
  const cur = VERBS.find((v) => v.id === on);
  return (
    <svg ref={ref} viewBox="0 0 640 216" role="img" aria-label="The six verbs on a ring: context, branch, try, check, request, report">
      <path d={RING} fill="none" stroke="rgba(11,16,21,.2)" strokeDasharray="2 4" />
      {!still && <rect width="7" height="7" x="-3.5" y="-3.5" fill="#0A7A4B"><animateMotion dur="14s" repeatCount="indefinite" path={RING} /></rect>}
      {VERBS.map((v, i) => {
        const [x, y] = pos(i);
        const a = v.id === on;
        return (
          <g key={v.id} className={`vn ${a ? "on" : ""}`}>
            <rect x={x - 40} y={y - 14} width="80" height="28" />
            <text x={x} y={y + 3.5} textAnchor="middle" className="mt">{v.id.toUpperCase()}</text>
          </g>
        );
      })}
      <text x={CX} y={CY - 3} textAnchor="middle" className="mt" style={{ fill: "rgba(11,16,21,.45)" }}>{cur ? cur.id.toUpperCase() : "SIX VERBS"}</text>
      <text x={CX} y={CY + 13} textAnchor="middle" style={{ fontSize: 13, fill: "rgba(11,16,21,.7)" }}>{cur ? cur.gloss : "one loop"}</text>
    </svg>
  );
}
export default VerbMap;
