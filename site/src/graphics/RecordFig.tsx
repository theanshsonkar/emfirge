"use client";
import { useRef } from "react";
import { comet, dotted, EDGE, GREEN, INK, lab, MUTED, RED_D, ramp, useTimeline, type Pt } from "./figkit";

// Figure: the record. After a pass: the verdict, then the hand-back bound to it by hash (emfirge, reads only), then the
// agent applies with its own access (emfirge has no apply path), then `report --verify` checks the binding: ok, or a 409 with a
// reason_code. Facts: site/FACTS.md:105 (report, hand-back fields, reason codes), backend/app/main.py:2191-2277 (reason_code
// values), how-it-works.ts "The record". Loops alternate: ok, then a rejected hand-back (input_hash_mismatch).
const T = 8;
type L = { vb: [number, number]; y0: number; vh: number; cls: string; tall: boolean; c: Pt[]; boxes: { x: number; y: number; w: number; h: number; t: string; agent?: boolean }[]; edges: Pt[][] };
const WC: Pt[] = [[64, 176], [164, 176], [300, 176], [436, 176], [536, 176]];
const WIDE: L = {
  vb: [640, 360], y0: 72, vh: 260, cls: "rf-w", tall: false, c: WC,
  boxes: [{ x: 24, y: 96, w: 188, h: 170, t: "EMFIRGE · READS ONLY" }, { x: 244, y: 96, w: 112, h: 170, t: "YOUR AGENT", agent: true }, { x: 388, y: 96, w: 228, h: 170, t: "EMFIRGE · READS ONLY" }],
  edges: [[[92, 176], [136, 176]], [[192, 176], [272, 176]], [[328, 176], [408, 176]], [[464, 176], [508, 176]]],
};
const TC: Pt[] = [[64, 64], [64, 148], [64, 268], [64, 384], [64, 468]];
const TALL: L = {
  vb: [320, 560], y0: 0, vh: 530, cls: "rf-t", tall: true, c: TC,
  boxes: [{ x: 16, y: 20, w: 288, h: 180, t: "EMFIRGE · READS ONLY" }, { x: 16, y: 224, w: 288, h: 92, t: "YOUR AGENT", agent: true }, { x: 16, y: 340, w: 288, h: 170, t: "EMFIRGE · READS ONLY" }],
  edges: [[[64, 92], [64, 120]], [[64, 176], [64, 240]], [[64, 296], [64, 356]], [[64, 412], [64, 440]]],
};
const ARIA = "Figure: the record. After a pass, emfirge hands back the exact calls bound by hash to the verdict. Your agent applies them with its own access; emfirge only reads and never writes. The agent runs report, and verify answers ok, or rejects the hand-back with a reason code such as input_hash_mismatch.";
const ICONS = [
  <g key="v" stroke="none"><rect x="-9" y="-6" width="5" height="12" fill={GREEN} opacity="1" /><rect x="-2.5" y="-6" width="5" height="12" fill="rgba(11,16,21,.12)" /><rect x="4" y="-6" width="5" height="12" fill="rgba(11,16,21,.12)" /></g>,
  <g key="h"><path d="M-6 -9H3L7 -5V9H-6Z" /><path d="M-3 -1H4M-3 3H4" strokeLinecap="square" /></g>,
  <g key="a"><rect x="-9" y="-6" width="18" height="14" /><path d="M0 -6V-11" /><path d="M-4 0V2M4 0V2" strokeLinecap="square" /><path d="M-13 0V3M13 0V3" /></g>,
  <g key="r"><path d="M-8 0H5M1 -4L5 0L1 4" strokeLinecap="square" /><path d="M9 -6V6" /></g>,
  <g key="k"><path d="M-7 0L-2 5L7 -5" strokeLinecap="square" strokeWidth="2" /></g>,
];
const TILE = ["VERDICT", "HAND-BACK", "APPLY", "REPORT", "VERIFY"];

function Draw({ L }: { L: L }) {
  const root = useRef<SVGSVGElement>(null);
  const { tall } = L;
  const small = { ...lab, fontSize: 9.5, letterSpacing: 0 } as const;
  const pts = (i: number): Pt[] => L.edges[i];
  const set = (svg: SVGSVGElement, k: string, kv: Record<string, string>) => { const e = svg.querySelector<SVGElement>(`[data-k="${k}"]`)!; for (const a in kv) e.setAttribute(a, kv[a]); return e; };
  const hot = (svg: SVGSVGElement, i: number, on: boolean) => set(svg, "t" + i, { stroke: on ? GREEN : EDGE, fill: on ? "rgba(10,122,75,.08)" : "#fff" });
  const result = (svg: SVGSVGElement, state: "ok" | "bad" | "none", k: number) => {
    const bad = state === "bad", c = bad ? RED_D : GREEN;
    set(svg, "t4", { fill: state === "none" ? "#fff" : bad ? "rgba(196,87,74,.1)" : "rgba(10,122,75,.1)", stroke: state === "none" ? EDGE : c });
    set(svg, "ico4", { stroke: state === "none" ? INK : c, opacity: state === "none" ? ".8" : "1", d: bad ? "M-6 -6L6 6M6 -6L-6 6" : "M-7 0L-2 5L7 -5" });
    const res = set(svg, "res", { fill: c, opacity: String(state === "none" ? 0 : k) }); res.textContent = bad ? "REJECTED" : "OK";
    const code = set(svg, "code", { fill: bad ? RED_D : MUTED, opacity: String(state === "none" ? 0 : k) }); code.textContent = bad ? "INPUT_HASH_MISMATCH" : "VERDICT: PASS";
  };
  useTimeline(root, T, 1, (t, n) => {
    const svg = root.current!;
    const bad = n % 2 === 1;
    const q = (k: string) => svg.querySelector<SVGElement>(`[data-k="${k}"]`)!;
    const fade = 1 - ramp(t, 7.3, T);
    hot(svg, 0, t < 1.4 && t >= 0);
    hot(svg, 1, t >= 1.0 && t < 2.4);
    hot(svg, 2, t >= 2.2 && t < 3.9);
    hot(svg, 3, t >= 3.9 && t < 4.8);
    comet(q("m0"), q("m0h"), pts(0), 0.35, 1.0, t, GREEN, 28);
    comet(q("m1"), q("m1h"), pts(1), 1.4, 2.2, t, GREEN, 40);
    comet(q("m2"), q("m2h"), pts(2), 3.6, 4.3, t, GREEN, 40);
    comet(q("m3"), q("m3h"), pts(3), 4.5, 5.1, t, GREEN, 28);
    const k = ramp(t, 5.1, 5.4) * fade;
    result(svg, t >= 5.1 ? (bad ? "bad" : "ok") : "none", k);
    if (t >= 5.1 && fade < 1) set(svg, "t4", { opacity: String(0.4 + 0.6 * fade) }); else set(svg, "t4", { opacity: "1" });
    const sub = q("asub");
    const flip = bad && t >= 2.4 && t < 7.3;
    sub.textContent = flip ? "OTHER CALLS" : "OWN ACCESS"; sub.setAttribute("fill", flip ? RED_D : MUTED);
    q("pulse").setAttribute("opacity", t >= 2.4 && t < 3.6 ? String(0.5 * (1 - ramp(t, 2.4, 3.6))) : "0");
  }, () => {
    const svg = root.current!;
    for (let i = 0; i < 4; i++) { hot(svg, i, false); set(svg, "m" + i, { opacity: "0" }); set(svg, "m" + i + "h", { opacity: "0" }); }
    result(svg, "ok", 1); set(svg, "pulse", { opacity: "0" });
  }, [L]);

  const T0 = (i: number) => L.c[i];
  return (
    <svg ref={root} className={`rf ${L.cls}`} viewBox={`0 ${L.y0} ${L.vb[0]} ${L.vh}`} role="img" aria-label={ARIA}>
      {L.edges.map((e, i) => <path key={i} d={"M" + e.map((p) => p.join(" ")).join("L")} {...dotted} />)}
      {/* owners: emfirge reads, the agent applies */}
      {L.boxes.map((b, i) => (
        <g key={i}>
          <rect x={b.x + 0.5} y={b.y + 0.5} width={b.w} height={b.h} fill={b.agent ? "rgba(11,16,21,.04)" : "none"} stroke={b.agent ? "rgba(11,16,21,.5)" : "rgba(11,16,21,.3)"} />
          <rect x={b.x + 10} y={b.y - 6} width={b.t.length * 7 + 12} height="14" fill={b.agent ? "#f5f6f6" : "#fff"} />
          <text x={b.x + 16} y={b.y + 5} {...lab} fill={INK}>{b.t}</text>
        </g>
      ))}
      <rect data-k="pulse" x={T0(2)[0] - 28} y={T0(2)[1] - 28} width="56" height="56" fill="none" stroke={GREEN} opacity="0" />
      {TILE.map((n, i) => {
        const [cx, cy] = T0(i);
        return (
          <g key={n}>
            <rect data-k={"t" + i} x={cx - 27.5} y={cy - 27.5} width="55" height="55" fill="#fff" stroke={EDGE} />
            <g transform={`translate(${cx} ${cy})`} fill="none" stroke={INK} strokeWidth="1.5" opacity=".8">
              {i === 4 ? <path data-k="ico4" d="M-7 0L-2 5L7 -5" strokeLinecap="square" strokeWidth="2" /> : ICONS[i]}
            </g>
          </g>
        );
      })}
      {tall ? (
        <>
          <text x="108" y="60" {...lab} fill={MUTED}>VERDICT</text>
          <text x="108" y="76" {...small} fill={MUTED}>PASS</text>
          <text x="108" y="140" {...lab} fill={MUTED}>HAND-BACK</text>
          <text x="108" y="156" {...small} fill={MUTED}>BOUND BY HASH TO:</text>
          <text x="108" y="170" {...small} fill={MUTED}>INPUT, BASE SCAN,</text>
          <text x="108" y="184" {...small} fill={MUTED}>REVISION, VERDICT ID</text>
          <text x="108" y="262" {...lab} fill={MUTED}>APPLY</text>
          <text data-k="asub" x="108" y="278" {...small} fill={MUTED}>OWN ACCESS</text>
          <text x="108" y="292" {...small} fill={INK}>EMFIRGE NEVER WRITES</text>
          <text x="108" y="380" {...lab} fill={MUTED}>REPORT</text>
          <text x="108" y="396" {...small} fill={MUTED}>CHECKS THE BINDING;</text>
          <text x="108" y="410" {...small} fill={MUTED}>READS NO CLOUDTRAIL</text>
          <text x="108" y="464" {...lab} fill={MUTED}>VERIFY</text>
          <text data-k="res" x="108" y="482" {...lab} fill={GREEN} opacity="0">OK</text>
          <text data-k="code" x="108" y="498" {...small} fill={MUTED} opacity="0">VERDICT: PASS</text>
        </>
      ) : (
        <>
          <text x="64" y="228" textAnchor="middle" {...lab} fill={MUTED}>VERDICT</text>
          <text x="64" y="244" textAnchor="middle" {...small} fill={MUTED}>PASS</text>
          <text x="164" y="228" textAnchor="middle" {...lab} fill={MUTED}>HAND-BACK</text>
          <text x="164" y="244" textAnchor="middle" {...small} fill={MUTED}>BOUND BY HASH</text>
          <text x="36" y="286" {...small} fill={MUTED}>BINDS INPUT HASH, BASE</text>
          <text x="36" y="300" {...small} fill={MUTED}>SCAN, REVISION, VERDICT ID</text>
          <text x="300" y="228" textAnchor="middle" {...lab} fill={MUTED}>APPLY</text>
          <text data-k="asub" x="300" y="244" textAnchor="middle" {...small} fill={MUTED}>OWN ACCESS</text>
          <text x="300" y="286" textAnchor="middle" {...small} fill={INK}>EMFIRGE NEVER</text>
          <text x="300" y="300" textAnchor="middle" {...small} fill={INK}>WRITES TO YOUR CLOUD</text>
          <text x="436" y="228" textAnchor="middle" {...lab} fill={MUTED}>REPORT</text>
          <text x="400" y="286" {...small} fill={MUTED}>CHECKS THE BINDING;</text>
          <text x="400" y="300" {...small} fill={MUTED}>READS NO CLOUDTRAIL</text>
          <text x="536" y="228" textAnchor="middle" {...lab} fill={MUTED}>VERIFY</text>
          <text data-k="res" x="536" y="246" textAnchor="middle" {...lab} fill={GREEN} opacity="0">OK</text>
          <text data-k="code" x="536" y="260" textAnchor="middle" {...small} fill={MUTED} opacity="0">VERDICT: PASS</text>
        </>
      )}
      {[0, 1, 2, 3].map((i) => (
        <g key={i}>
          <path data-k={"m" + i} d="M0 0" fill="none" strokeWidth="2" strokeLinecap="square" opacity="0" stroke={GREEN} />
          <rect data-k={"m" + i + "h"} width="4" height="4" opacity="0" fill={GREEN} />
        </g>
      ))}
    </svg>
  );
}
export function RecordFig() { return (<><Draw L={WIDE} /><Draw L={TALL} /></>); }
export default RecordFig;
