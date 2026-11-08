"use client";
import { useEffect, useState } from "react";
import { useLive } from "./useLive";

// CLI figure: the six verbs in a loop, with arrows in order (context, branch, try, check, request, report, back to context).
// The verb for the section being read is highlighted (Shell's scroll-spy sends `emfirge:spy`).
// A wide drawing is a ring; phones get the same loop as a vertical list with the return line down the side.
const VERBS = [
  { id: "context", gloss: "what is true" },
  { id: "branch", gloss: "a copy to work on" },
  { id: "try", gloss: "put a change on it" },
  { id: "check", gloss: "six facts back" },
  { id: "request", gloss: "ask the owner (not built yet)" },
  { id: "report", gloss: "the hand-back" },
];
const LINE = "rgba(11,16,21,.5)";

function useSpy() {
  const [on, setOn] = useState<string | null>(null);
  useEffect(() => {
    const w = window as unknown as { __spy?: string };
    setOn(w.__spy ?? null);
    const h = (e: Event) => setOn((e as CustomEvent<string>).detail);
    window.addEventListener("emfirge:spy", h);
    return () => window.removeEventListener("emfirge:spy", h);
  }, []);
  return on;
}

function usePlay(ref: React.RefObject<SVGSVGElement | null>, live: boolean, still: boolean) {
  useEffect(() => {
    const s = ref.current as unknown as SVGSVGElement & { pauseAnimations?: () => void; unpauseAnimations?: () => void };
    if (!s?.pauseAnimations) return;
    if (live && !still) s.unpauseAnimations?.(); else s.pauseAnimations?.();
  }, [live, still, ref]);
}

// An arrowhead at (x, y) pointing along angle `a` (radians, screen space).
const Arrow = ({ x, y, a }: { x: number; y: number; a: number }) => (
  <path d="M-5 -4L2 0L-5 4" transform={`translate(${x} ${y}) rotate(${(a * 180) / Math.PI})`} fill="none" stroke={LINE} strokeWidth="1.4" />
);

/* ---- wide: the ring ---- */
const CX = 320, CY = 108, RX = 236, RY = 66;
const ang = (i: number) => ((180 + 60 * i) * Math.PI) / 180;
const pos = (i: number): [number, number] => [CX + RX * Math.cos(ang(i)), CY + RY * Math.sin(ang(i))];
const RING = `M ${CX - RX} ${CY} A ${RX} ${RY} 0 1 1 ${CX + RX} ${CY} A ${RX} ${RY} 0 1 1 ${CX - RX} ${CY}`;

function Ring() {
  const { ref, live, still } = useLive<SVGSVGElement>();
  const on = useSpy();
  usePlay(ref, live, still);
  const cur = VERBS.find((v) => v.id === on);
  return (
    <svg ref={ref} className="vm vm-w" viewBox="0 0 640 216" role="img" aria-label="The six verbs in a loop: context, branch, try, check, request, report, and back to context">
      <path d={RING} fill="none" stroke={LINE} strokeWidth="1.25" />
      {/* one arrow on each of the six arcs, pointing the way round */}
      {VERBS.map((v, i) => {
        const t = ang(i) + Math.PI / 6;
        const x = CX + RX * Math.cos(t), y = CY + RY * Math.sin(t);
        const tangent = Math.atan2(RY * Math.cos(t), -RX * Math.sin(t));
        return <Arrow key={v.id} x={x} y={y} a={tangent} />;
      })}
      {!still && <rect width="7" height="7" x="-3.5" y="-3.5" fill="#0A7A4B"><animateMotion dur="14s" repeatCount="indefinite" path={RING} /></rect>}
      {VERBS.map((v, i) => {
        const [x, y] = pos(i);
        return (
          <g key={v.id} className={`vn ${v.id === on ? "on" : ""}`}>
            <rect x={x - 40} y={y - 14} width="80" height="28" />
            <text x={x} y={y + 4} textAnchor="middle" className="mt">{v.id.toUpperCase()}</text>
          </g>
        );
      })}
      <text x={CX} y={CY - 3} textAnchor="middle" className="mt" style={{ fill: "rgba(11,16,21,.6)" }}>{cur ? cur.id.toUpperCase() : "SIX VERBS"}</text>
      <text x={CX} y={CY + 14} textAnchor="middle" style={{ fontSize: 13, fill: "rgba(11,16,21,.75)" }}>{cur ? cur.gloss : "one loop"}</text>
    </svg>
  );
}

/* ---- phone: the list ---- */
const BX = 34, BW = 96, BH = 30, ROW = 64, Y0 = 24, LX = 14;
const cy = (i: number) => Y0 + i * ROW;
const LOOP = `M ${BX + BW / 2} ${cy(0)} V ${cy(5)} H ${LX} V ${cy(0)} H ${BX + BW / 2}`;

function Stack() {
  const { ref, live, still } = useLive<SVGSVGElement>();
  const on = useSpy();
  usePlay(ref, live, still);
  const cx = BX + BW / 2;
  return (
    <svg ref={ref} className="vm vm-t" viewBox="0 0 320 372" role="img" aria-label="The six verbs in a loop: context, branch, try, check, request, report, and back to context">
      {/* down the list */}
      {VERBS.slice(0, 5).map((v, i) => (
        <g key={v.id}>
          <path d={`M${cx} ${cy(i) + BH / 2}V${cy(i + 1) - BH / 2 - 5}`} stroke={LINE} strokeWidth="1.25" fill="none" />
          <Arrow x={cx} y={cy(i + 1) - BH / 2 - 1} a={Math.PI / 2} />
        </g>
      ))}
      {/* back to the start: report, round the side, into context */}
      <path d={`M${BX} ${cy(5)}H${LX}V${cy(0)}H${BX - 5}`} stroke={LINE} strokeWidth="1.25" fill="none" />
      <Arrow x={BX - 1} y={cy(0)} a={0} />
      {!still && <rect width="7" height="7" x="-3.5" y="-3.5" fill="#0A7A4B"><animateMotion dur="14s" repeatCount="indefinite" path={LOOP} /></rect>}
      {VERBS.map((v, i) => (
        <g key={v.id} className={`vn ${v.id === on ? "on" : ""}`}>
          <rect x={BX} y={cy(i) - BH / 2} width={BW} height={BH} />
          <text x={cx} y={cy(i) + 4} textAnchor="middle" className="mt">{v.id.toUpperCase()}</text>
          <text x={BX + BW + 16} y={cy(i) + 4.5} className="vg" style={{ fontSize: 13, fill: v.id === on ? "#0B1015" : "rgba(11,16,21,.75)" }}>{v.gloss}</text>
        </g>
      ))}
    </svg>
  );
}

export function VerbMap() {
  return (<><Ring /><Stack /></>);
}
export default VerbMap;
