"use client";
import { useRef } from "react";
import { comet, dotted, EDGE, GREEN, INK, lab, MUTED, SOFT, ramp, useTimeline, type Pt } from "./figkit";

// Figure: the six checks. One change fans out to six answers, always in this order. Each answer is facts + unknown
// (never a verdict: backend/app/check_facts.py:1-19). The example is the page's SSH-rule check: exposure has a fact, availability
// has `recent_use` unknown. The older verdict (pass/warn/block, worst reason wins: backend/app/verdict.py:857-858) is fed
// only by data, exposure and availability reasons; money, control and outside world have no reason code.
const T = 6.8;
const NAMES = ["DATA", "EXPOSURE", "MONEY", "AVAILABILITY", "CONTROL", "OUTSIDE WORLD"];
const QS = ["DELETED, NO RECOVERY?", "NEWLY REACHABLE?", "MONTHLY COST CHANGE?", "LIVE TRAFFIC BROKEN?", "WHO CAN DO WHAT?", "LEAVES THE CLOUD?"];
const FACT = [false, true, false, false, false, false];
const FEED = [0, 1, 3]; // checks that have reason codes in the verdict
const G = [
  <g key="d"><ellipse cx="0" cy="-6" rx="7.5" ry="3" /><path d="M-7.5 -6V6C-7.5 9.5 7.5 9.5 7.5 6V-6" /><path d="M-7.5 0C-7.5 3.5 7.5 3.5 7.5 0" /></g>,
  <g key="e"><circle cx="0" cy="0" r="8" /><ellipse cx="0" cy="0" rx="3.5" ry="8" /><path d="M-8 0H8" /></g>,
  <g key="m"><circle cx="0" cy="0" r="8" /><path d="M-3.5 -2.5H3.5M-3.5 2.5H3.5" strokeLinecap="square" /></g>,
  <g key="a"><rect x="-2.5" y="-9" width="5" height="5" /><rect x="-9" y="3" width="5" height="5" /><rect x="4" y="3" width="5" height="5" /><path d="M0 -4V0M0 0H-6.5V3M0 0H6.5V3" /></g>,
  <g key="c"><circle cx="-4.5" cy="0" r="3.5" /><path d="M-1 0H9M6 0V4M9 0V3" strokeLinecap="square" /></g>,
  <g key="o"><path d="M3 -6H-7V7H6V-3" /><path d="M-1 1L8 -8M3 -8H8V-3" strokeLinecap="square" /></g>,
];

type L = { vb: [number, number]; cls: string; card: (i: number) => { x: number; y: number }; w: number; h: number;
  fan: (i: number) => Pt[]; conv: (i: number) => Pt[]; chg: { x: number; y: number }; ver: { x: number; y: number }; tall: boolean };
const WIDE: L = {
  vb: [640, 360], cls: "cf-w", w: 300, h: 40, tall: false,
  card: (i) => ({ x: 168, y: 48 + 46 * i }),
  fan: (i) => [[96, 183], [132, 183], [132, 68 + 46 * i], [168, 68 + 46 * i]],
  conv: (i) => [[468, 68 + 46 * i], [484, 68 + 46 * i], [484, 183], [512, 183]],
  chg: { x: 40, y: 155 }, ver: { x: 512, y: 155 },
};
const TALL: L = {
  vb: [320, 532], cls: "cf-t", w: 272, h: 42, tall: true,
  card: (i) => ({ x: 24, y: 108 + 50 * i }),
  fan: (i) => [[24, 52], [12, 52], [12, 129 + 50 * i], [24, 129 + 50 * i]],
  conv: (i) => [[296, 129 + 50 * i], [308, 129 + 50 * i], [308, 452], [296, 452]],
  chg: { x: 24, y: 24 }, ver: { x: 240, y: 424 },
};
const ARIA = "Figure: the six checks. One change from a branch is asked six questions in a fixed order: data, exposure, money, availability, control and outside world. Each answers with facts and with what is unknown; none answers pass. A separate verdict, pass, warn or block, takes the worst reason, and a change emfirge cannot model never passes.";
const chipW = 60;

function Draw({ L }: { L: L }) {
  const root = useRef<SVGSVGElement>(null);
  const { tall } = L;
  const vx = L.ver.x, vy = L.ver.y;
  useTimeline(root, T, 1, (t) => {
    const svg = root.current!;
    const q = (k: string) => svg.querySelector<SVGElement>(`[data-k="${k}"]`)!;
    q("chg").setAttribute("stroke", t < 3.4 ? GREEN : EDGE);
    q("chg").setAttribute("fill", t < 3.4 && t > 0 ? "rgba(10,122,75,.1)" : "#fff");
    const fade = 1 - ramp(t, 6.2, T);
    for (let i = 0; i < 6; i++) {
      const a = 0.3 + 0.45 * i, b = a + 0.5;
      comet(q("c" + i), q("c" + i + "h"), L.fan(i), a, b, t, GREEN, 30);
      const hot = t >= a + 0.3 && t < b + 0.35;
      q("card" + i).setAttribute("stroke", hot ? GREEN : EDGE);
      q("card" + i).setAttribute("fill", hot ? "rgba(10,122,75,.06)" : "#fff");
      const on = ramp(t, b - 0.05, b + 0.2) * fade;
      q("chips" + i).setAttribute("opacity", String(on));
    }
    FEED.forEach((i, j) => comet(q("v" + j), q("v" + j + "h"), L.conv(i), 3.5, 4.2, t, FACT[i] ? INK : GREEN, 30));
    const w = ramp(t, 4.2, 4.5) * fade;
    q("cellW").setAttribute("fill", w > 0.01 ? INK : SOFT); q("cellW").setAttribute("opacity", w > 0.01 ? String(w) : "1");
    q("verb").setAttribute("opacity", String(w));
    q("ver").setAttribute("stroke", w > 0.5 ? INK : EDGE);
  }, () => {
    const svg = root.current!;
    const q = (k: string) => svg.querySelector<SVGElement>(`[data-k="${k}"]`)!;
    for (let i = 0; i < 6; i++) { q("chips" + i).setAttribute("opacity", "1"); q("card" + i).setAttribute("stroke", EDGE); q("card" + i).setAttribute("fill", "#fff"); q("c" + i).setAttribute("opacity", "0"); q("c" + i + "h").setAttribute("opacity", "0"); }
    [0, 1, 2].forEach((j) => { q("v" + j).setAttribute("opacity", "0"); q("v" + j + "h").setAttribute("opacity", "0"); });
    q("cellW").setAttribute("fill", INK); q("cellW").setAttribute("opacity", "1"); q("verb").setAttribute("opacity", "1"); q("ver").setAttribute("stroke", INK);
    q("chg").setAttribute("stroke", EDGE); q("chg").setAttribute("fill", "#fff");
  }, [L]);

  const cx = vx + 28;
  const small = { ...lab, fontSize: 9.5, letterSpacing: 0 } as const;
  return (
    <svg ref={root} className={`cf ${L.cls}`} viewBox={`0 0 ${L.vb[0]} ${L.vb[1]}`} role="img" aria-label={ARIA}>
      {/* edges */}
      {[0, 1, 2, 3, 4, 5].map((i) => <path key={"f" + i} d={"M" + L.fan(i).map((p) => p.join(" ")).join("L")} {...dotted} />)}
      {FEED.map((i) => <path key={"g" + i} d={"M" + L.conv(i).map((p) => p.join(" ")).join("L")} {...dotted} />)}
      {/* the change */}
      <rect data-k="chg" x={L.chg.x + 0.5} y={L.chg.y + 0.5} width="55" height="55" fill="#fff" stroke={EDGE} />
      <g transform={`translate(${L.chg.x + 28} ${L.chg.y + 28})`}>
        <g transform="scale(1.1) translate(-12 -12)" fill="none" stroke={GREEN} strokeWidth="2" strokeLinecap="square"><path d="M2.5 15H21.5" /><path d="M9 15C13.5 15 13.5 7 21.5 7" opacity=".7" /></g>
      </g>
      {tall ? (
        <>
          <text x="92" y="48" {...lab} fill={MUTED}>ONE CHANGE</text>
          <text x="92" y="64" {...small} fill={MUTED}>FROM A BRANCH</text>
        </>
      ) : (
        <>
          <text x={L.chg.x + 28} y="232" textAnchor="middle" {...lab} fill={MUTED}>ONE CHANGE</text>
          <text x={L.chg.x + 28} y="248" textAnchor="middle" {...small} fill={MUTED}>FROM A BRANCH</text>
        </>
      )}
      {/* six checks */}
      {NAMES.map((n, i) => {
        const { x, y } = L.card(i);
        const h = L.h, w = L.w;
        const cw = tall ? 58 : chipW;
        return (
          <g key={n}>
            <rect data-k={"card" + i} x={x + 0.5} y={y + 0.5} width={w - 1} height={h - 1} fill="#fff" stroke={EDGE} />
            <g transform={`translate(${x + h / 2} ${y + h / 2}) scale(.9)`} fill="none" stroke={INK} strokeWidth="1.4" opacity=".8">{G[i]}</g>
            <path d={`M${x + h + 0.5} ${y + 6}V${y + h - 6}`} stroke={EDGE} />
            <text x={x + h + 10} y={y + h / 2 - 2} {...lab} fill={INK} fontSize={tall && i === 5 ? 10 : 11} letterSpacing={tall ? 0.2 : 0.5}>{n}</text>
            <text x={x + h + 10} y={y + h / 2 + 12} {...small} fill={MUTED}>{QS[i]}</text>
            <g data-k={"chips" + i} opacity="0">
              {FACT[i]
                ? <><rect x={x + w - 8 - cw} y={y + 5} width={cw} height="14" fill={INK} /><text x={x + w - 8 - cw / 2} y={y + 15} textAnchor="middle" {...small} fill="#fff">FACT</text></>
                : <><rect x={x + w - 8 - cw + 0.5} y={y + 5.5} width={cw - 1} height="13" fill="none" stroke={EDGE} /><text x={x + w - 8 - cw / 2} y={y + 15} textAnchor="middle" {...small} fill={MUTED}>NO FACTS</text></>}
              <rect x={x + w - 8 - cw + 0.5} y={y + h - 19.5} width={cw - 1} height="13" fill="none" stroke="rgba(11,16,21,.5)" strokeDasharray="2 2" />
              <text x={x + w - 8 - cw / 2} y={y + h - 9.5} textAnchor="middle" {...small} fill={INK}>UNKNOWN</text>
            </g>
          </g>
        );
      })}
      {/* verdict */}
      <rect data-k="ver" x={vx + 0.5} y={vy + 0.5} width="55" height="55" fill="#fff" stroke={EDGE} />
      <rect x={vx + 4} y={vy + 22} width="12" height="12" fill={SOFT} />
      <rect data-k="cellW" x={vx + 22} y={vy + 22} width="12" height="12" fill={SOFT} />
      <rect x={vx + 40} y={vy + 22} width="12" height="12" fill={SOFT} />
      {tall ? (
        <>
          <text x="24" y="438" {...lab} fill={MUTED}>VERDICT</text>
          <text x="24" y="456" {...small} fill={MUTED}>WORST REASON WINS</text>
          <text x="24" y="470" {...small} fill={MUTED}>UNMODELED NEVER PASSES</text>
          <text data-k="verb" x={cx} y="498" textAnchor="middle" {...lab} fill={INK} opacity="0">WARN</text>
          <text x="24" y="504" {...small} fill={MUTED}>MONEY, CONTROL, OUTSIDE</text>
          <text x="24" y="518" {...small} fill={MUTED}>WORLD: NO REASON CODE</text>
        </>
      ) : (
        <>
          <text x={cx} y="232" textAnchor="middle" {...lab} fill={MUTED}>VERDICT</text>
          <text data-k="verb" x={cx} y="249" textAnchor="middle" {...lab} fill={INK} opacity="0">WARN</text>
          <text x={cx} y="272" textAnchor="middle" {...small} fill={MUTED}>WORST REASON WINS</text>
          <text x={cx} y="286" textAnchor="middle" {...small} fill={MUTED}>UNMODELED NEVER</text>
          <text x={cx} y="300" textAnchor="middle" {...small} fill={MUTED}>PASSES</text>
          <text x="496" y="56" {...small} fill={MUTED}>NO REASON CODE:</text>
          <text x="496" y="70" {...small} fill={MUTED}>MONEY, CONTROL,</text>
          <text x="496" y="84" {...small} fill={MUTED}>OUTSIDE WORLD</text>
        </>
      )}
      {/* comets: six answers going out, three reasons going in */}
      {[...Array(6).keys()].map((i) => (
        <g key={i}>
          <path data-k={"c" + i} d="M0 0" fill="none" strokeWidth="2" strokeLinecap="square" opacity="0" stroke={GREEN} />
          <rect data-k={"c" + i + "h"} width="4" height="4" opacity="0" fill={GREEN} />
        </g>
      ))}
      {[0, 1, 2].map((j) => (
        <g key={"v" + j}>
          <path data-k={"v" + j} d="M0 0" fill="none" strokeWidth="2" strokeLinecap="square" opacity="0" stroke={GREEN} />
          <rect data-k={"v" + j + "h"} width="4" height="4" opacity="0" fill={GREEN} />
        </g>
      ))}
    </svg>
  );
}
export function ChecksFig() { return (<><Draw L={WIDE} /><Draw L={TALL} /></>); }
export default ChecksFig;
