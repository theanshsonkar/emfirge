"use client";
import { useEffect, useRef } from "react";

// Figure 1: the Emfirge loop, run by one small timeline. Everything is in a 640x360 SVG.
// A source lights up, a comet rides the edge into the group, verbs cycle try/check/block/retry/pass,
// six cells fill (one fails), a red comet returns, the branch number rolls #1 -> #2, six green cells,
// then a comet carries "pass" to the agent's context.
const T = 7.8, SPEED = 1.18;
const INK = "#0B1015", GREEN = "#0A7A4B", RED = "#C4574A";
const SRC_Y = [88, 176, 264];
type Pt = [number, number];
const srcPath = (i: number): Pt[] => [[96, SRC_Y[i]], [124, SRC_Y[i]], [124, 176], [176, 176]];
const MID: Pt[] = [[240, 176], [368, 176]];
const OUT: Pt[] = [[432, 176], [456, 176], [508, 176]];

const clamp = (x: number, a = 0, b = 1) => Math.min(b, Math.max(a, x));
const ramp = (t: number, a: number, b: number) => clamp((t - a) / (b - a));
const ease = (x: number) => 1 - Math.pow(1 - x, 3);
const plen = (p: Pt[]) => p.slice(1).reduce((s, q, i) => s + Math.hypot(q[0] - p[i][0], q[1] - p[i][1]), 0);
function pointAt(p: Pt[], d: number): Pt {
  let rem = d;
  for (let i = 1; i < p.length; i++) {
    const l = Math.hypot(p[i][0] - p[i - 1][0], p[i][1] - p[i - 1][1]);
    if (rem <= l || i === p.length - 1) { const k = clamp(rem / (l || 1)); return [p[i - 1][0] + (p[i][0] - p[i - 1][0]) * k, p[i - 1][1] + (p[i][1] - p[i - 1][1]) * k]; }
    rem -= l;
  }
  return p[p.length - 1];
}
function cometD(p: Pt[], head: number, tail = 34): string {
  const L = plen(p), h = clamp(head) * L, s = Math.max(0, h - tail);
  const pts: Pt[] = [pointAt(p, s)];
  let acc = 0;
  for (let i = 1; i < p.length; i++) { acc += Math.hypot(p[i][0] - p[i - 1][0], p[i][1] - p[i - 1][1]); if (acc > s && acc < h) pts.push(p[i]); }
  pts.push(pointAt(p, h));
  return "M" + pts.map((q) => q.map((n) => n.toFixed(1)).join(" ")).join("L");
}
const rev = (p: Pt[]) => [...p].reverse();

export function Figure1() {
  const root = useRef<SVGSVGElement>(null);
  useEffect(() => {
    const svg = root.current!;
    const q = (k: string) => svg.querySelector<SVGElement>(`[data-k="${k}"]`)!;
    const el = {
      src: [0, 1, 2].map((i) => q("src" + i)), srcLab: [0, 1, 2].map((i) => q("srclab" + i)),
      c1: q("c1"), c2: q("c2"), c3: q("c3"), c4: q("c4"), c5: q("c5"),
      c1h: q("c1h"), c2h: q("c2h"), c3h: q("c3h"), c4h: q("c4h"), c5h: q("c5h"),
      ring: q("ring"), verb: q("verb"), cells: [0, 1, 2, 3, 4, 5].map((i) => q("cell" + i)),
      n1: q("n1"), n2: q("n2"), agent: q("agent"), fact: q("fact"), box: q("boxlab"), strip: q("strip"), stripT: q("stripT"),
      checks: q("checks"),
    };
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    let loopN = 0, lastLoop = -1;

    const comet = (path: SVGElement, head: SVGElement, p: Pt[], a: number, b: number, t: number, color: string, tail = 34) => {
      const f = ramp(t, a, b);
      if (f <= 0 || f >= 1) { path.setAttribute("opacity", "0"); head.setAttribute("opacity", "0"); return; }
      path.setAttribute("d", cometD(p, ease(f), tail));
      path.setAttribute("stroke", color);
      path.setAttribute("opacity", String(Math.min(1, f * 6, (1 - f) * 6)));
      const pt = pointAt(p, ease(f) * plen(p));
      head.setAttribute("x", String(pt[0] - 2)); head.setAttribute("y", String(pt[1] - 2));
      head.setAttribute("fill", color);
      head.setAttribute("opacity", String(Math.min(1, f * 6, (1 - f) * 6)));
    };
    const still = () => {
      [el.c1, el.c2, el.c3, el.c4, el.c5, el.c1h, el.c2h, el.c3h, el.c4h, el.c5h, el.ring].forEach((e) => e.setAttribute("opacity", "0"));
      el.src.forEach((e, i) => { e.setAttribute("stroke", "rgba(11,16,21,.22)"); e.setAttribute("fill", "#fff"); el.srcLab[i].setAttribute("fill", "rgba(11,16,21,.6)"); });
      el.cells.forEach((c) => { c.setAttribute("fill", GREEN); c.setAttribute("opacity", "1"); });
      el.verb.textContent = "PASS"; el.verb.setAttribute("fill", GREEN); el.verb.setAttribute("opacity", "1");
      el.n1.setAttribute("opacity", "0"); el.n2.setAttribute("opacity", "1"); el.n2.setAttribute("transform", "translate(0 0)");
      el.agent.setAttribute("stroke", GREEN); el.agent.setAttribute("fill", "rgba(10,122,75,.07)");
      el.fact.setAttribute("fill", GREEN);
      el.stripT.setAttribute("fill", GREEN);
    };
    const apply = (t: number, now: number) => {
      const n = Math.floor(now / T);
      if (n !== lastLoop) { lastLoop = n; loopN = n; }
      const s = loopN % 3;
      // source hot
      el.src.forEach((e, i) => {
        const hot = i === s ? ramp(t, 0.0, 0.25) * (1 - ramp(t, 1.0, 1.5)) : 0;
        e.setAttribute("stroke", hot > 0.02 ? GREEN : "rgba(11,16,21,.22)");
        e.setAttribute("fill", hot > 0.02 ? `rgba(10,122,75,${0.06 + 0.06 * hot})` : "#fff");
        el.srcLab[i].setAttribute("fill", hot > 0.02 ? GREEN : "rgba(11,16,21,.6)");
      });
      comet(el.c1, el.c1h, srcPath(s), 0.25, 1.25, t, GREEN);
      comet(el.c2, el.c2h, MID, 1.55, 2.1, t, GREEN, 40);
      comet(el.c3, el.c3h, rev(srcPath(s)), 3.7, 4.8, t, RED);
      comet(el.c4, el.c4h, MID, 4.95, 5.5, t, GREEN, 40);
      comet(el.c5, el.c5h, OUT, 5.95, 6.7, t, GREEN);
      // ring pulse on the branch tile when a change lands
      const rp = ramp(t, 1.2, 1.9);
      el.ring.setAttribute("opacity", String(rp > 0 && rp < 1 ? 0.6 * (1 - rp) : 0));
      el.ring.setAttribute("transform", `translate(208 176) scale(${1 + rp * 0.18}) translate(-208 -176)`);
      // verbs
      const verbs: [number, number, string, string][] = [[1.2, 2.1, "TRY", GREEN], [2.1, 3.7, "CHECK", GREEN], [3.7, 4.5, "BLOCK", RED], [4.5, 5.9, "RETRY", GREEN], [5.9, 7.5, "PASS", GREEN]];
      const v = verbs.find((x) => t >= x[0] && t < x[1]);
      if (v) { el.verb.textContent = v[2]; el.verb.setAttribute("fill", v[3]); el.verb.setAttribute("opacity", String(0.7 + 0.3 * Math.sin(t * 7))); }
      else { el.verb.textContent = ""; }
      // cells
      for (let i = 0; i < 6; i++) {
        let fill = "rgba(11,16,21,.1)", op = 1;
        const a = 2.2 + 0.22 * i;
        if (t >= 4.6 && t < 5.9) { const b = 5.15 + 0.1 * i; if (t >= b) fill = GREEN; }
        else if (t >= 5.9 && t < 7.5) fill = GREEN;
        else if (t >= a && t < 4.6) fill = i === 3 && t >= a ? RED : GREEN;
        else if (t >= 7.5) { fill = GREEN; op = 1 - ramp(t, 7.5, T); }
        el.cells[i].setAttribute("fill", fill); el.cells[i].setAttribute("opacity", String(op));
      }
      // checks tile edge flashes red on block
      el.checks.setAttribute("stroke", t >= 3.5 && t < 4.5 ? RED : t >= 5.9 && t < 7.4 ? GREEN : "rgba(11,16,21,.22)");
      // branch counter roll #1 -> #2
      const r = ramp(t, 4.5, 5.0);
      el.n1.setAttribute("opacity", String(1 - r)); el.n1.setAttribute("transform", `translate(0 ${-8 * r})`);
      el.n2.setAttribute("opacity", String(r)); el.n2.setAttribute("transform", `translate(0 ${8 * (1 - r)})`);
      if (t >= 7.5) { const k = ramp(t, 7.5, T); el.n1.setAttribute("opacity", String(k)); el.n1.setAttribute("transform", "translate(0 0)"); el.n2.setAttribute("opacity", String(1 - k)); el.n2.setAttribute("transform", `translate(0 ${8 * k})`); }
      // agent
      const ag = t >= 6.6 && t < 7.5 ? ramp(t, 6.6, 6.9) : t >= 7.5 ? 1 - ramp(t, 7.5, T) : 0;
      el.agent.setAttribute("stroke", ag > 0.02 ? GREEN : "rgba(11,16,21,.22)");
      el.agent.setAttribute("fill", ag > 0.02 ? `rgba(10,122,75,${0.08 * ag})` : "#fff");
      el.fact.setAttribute("fill", ag > 0.02 ? GREEN : "rgba(11,16,21,.6)");
      // strip text lights while a change is inside the group
      const inside = t > 1.2 && t < 6.9 ? 1 : 0;
      el.stripT.setAttribute("fill", inside ? GREEN : "rgba(11,16,21,.45)");
    };

    let raf = 0, visible = false, start = performance.now(), running = false, paused = 0;
    const frame = (now: number) => {
      raf = 0; if (!running) return;
      const sec = ((now - start) / 1000) * SPEED;
      apply(sec % T, sec);
      raf = requestAnimationFrame(frame);
    };
    const update = () => {
      const should = visible && !document.hidden && !mq.matches;
      if (should && !running) { running = true; start = performance.now() - paused; raf = requestAnimationFrame(frame); }
      else if (!should && running) { running = false; paused = performance.now() - start; if (raf) cancelAnimationFrame(raf); raf = 0; }
    };
    if (mq.matches) still(); else apply(0, 0);
    const io = new IntersectionObserver((e) => { visible = e[0].isIntersecting; update(); });
    io.observe(svg);
    const onMq = () => { if (mq.matches) { update(); still(); } else update(); };
    mq.addEventListener("change", onMq);
    document.addEventListener("visibilitychange", update);
    return () => { running = false; if (raf) cancelAnimationFrame(raf); io.disconnect(); mq.removeEventListener("change", onMq); document.removeEventListener("visibilitychange", update); };
  }, []);

  const lab = { fontFamily: "var(--font-geist-mono), monospace", fontSize: 9, letterSpacing: 0.9, fontWeight: 500 } as const;
  const dotted = { stroke: "rgba(11,16,21,.38)", strokeWidth: 1, strokeDasharray: "1 3", fill: "none" } as const;
  const icons = [
    <g key="cli" fill="none" stroke={INK} strokeWidth="1.5" strokeLinecap="square" opacity=".8"><path d="M-7 -5L-1 0L-7 5" /><path d="M2 6H8" /></g>,
    <g key="tf" fill="none" stroke={INK} strokeWidth="1.4" opacity=".8"><path d="M-8 -7L-2 -4V3L-8 0Z" /><path d="M0 -3L6 -6V1L0 4Z" /><path d="M-2 5L4 2V8L-2 11Z" transform="translate(0 -2)" /></g>,
    <g key="cfn" fill="none" stroke={INK} strokeWidth="1.5" strokeLinecap="square" opacity=".8"><path d="M-3 -7C-7 -7 -6 -1 -9 0C-6 1 -7 7 -3 7" /><path d="M3 -7C7 -7 6 -1 9 0C6 1 7 7 3 7" /></g>,
  ];
  const srcNames = ["AWS CLI", "TERRAFORM", "CLOUDFORMATION"];
  return (
    <svg ref={root} viewBox="0 0 640 360" role="img" aria-label="Figure 1: a change enters Emfirge, runs on a branch, six checks answer, a block returns to the agent, and a pass reaches the agent's context.">
      <text x="40" y="44" {...lab} fill="rgba(11,16,21,.6)">CHANGES</text>
      {/* edges */}
      <path d="M96 88H124V264M96 176H124M96 264H124M124 176H176" {...dotted} />
      <path d="M152 176H124" {...dotted} />
      <path d="M240 176H368" {...dotted} />
      <path d="M432 176H508" {...dotted} />
      {/* sources */}
      {SRC_Y.map((y, i) => (
        <g key={i}>
          <rect data-k={"src" + i} x="40.5" y={y - 28 + 0.5} width="55" height="55" fill="#fff" stroke="rgba(11,16,21,.22)" />
          <g transform={`translate(68 ${y})`}>{icons[i]}</g>
          <text data-k={"srclab" + i} x="68" y={y + 44} textAnchor="middle" {...lab} fontSize={i === 2 ? 8 : 9} fill="rgba(11,16,21,.6)">{srcNames[i]}</text>
        </g>
      ))}
      {/* group */}
      <rect x="152.5" y="96.5" width="303" height="170" fill="none" stroke="rgba(11,16,21,.3)" />
      <rect x="164" y="90" width="58" height="14" fill="#fff" />
      <text data-k="boxlab" x="170" y="100" {...lab} fill={INK}>EMFIRGE</text>
      <rect x="168.5" y="112.5" width="271" height="22" fill="none" stroke="rgba(11,16,21,.3)" strokeDasharray="3 3" />
      <text data-k="stripT" x="304" y="127" textAnchor="middle" {...lab} fill="rgba(11,16,21,.45)">A BRANCH OF YOUR LIVE CLOUD</text>
      {/* branch tile */}
      <rect x="176" y="144" width="64" height="64" fill={GREEN} />
      <rect data-k="ring" x="176.5" y="144.5" width="63" height="63" fill="none" stroke={GREEN} opacity="0" />
      <g transform="translate(208 176) scale(1.6) translate(-12 -12)" fill="none" strokeWidth="2.2" strokeLinecap="square">
        <path d="M2.5 15H21.5" stroke="#fff" /><path d="M9 15C13.5 15 13.5 7 21.5 7" stroke="#fff" opacity=".7" />
      </g>
      <text x="208" y="228" textAnchor="middle" {...lab} fill="rgba(11,16,21,.6)">BRANCH</text>
      <text data-k="verb" x="304" y="171" textAnchor="middle" {...lab} fill="rgba(11,16,21,.5)" />
      {/* checks tile */}
      <rect data-k="checks" x="368.5" y="144.5" width="63" height="63" fill="#fff" stroke="rgba(11,16,21,.22)" />
      {[0, 1, 2, 3, 4, 5].map((i) => (
        <rect key={i} data-k={"cell" + i} x={376 + (i % 3) * 18} y={161 + Math.floor(i / 3) * 18} width="12" height="12" fill="rgba(11,16,21,.1)" />
      ))}
      <text x="400" y="228" textAnchor="middle" {...lab} fill="rgba(11,16,21,.6)">CHECKS</text>
      <g fill={GREEN} {...lab}>
        <text data-k="n1" x="400" y="244" textAnchor="middle" fill={GREEN}>BRANCH #1</text>
        <text data-k="n2" x="400" y="244" textAnchor="middle" fill={GREEN} opacity="0">BRANCH #2</text>
      </g>
      {/* agent */}
      <text data-k="fact" x="536" y="128" textAnchor="middle" {...lab} fill="rgba(11,16,21,.6)">FACTS VIA CLI</text>
      <rect data-k="agent" x="508.5" y="148.5" width="55" height="55" fill="#fff" stroke="rgba(11,16,21,.22)" />
      <g transform="translate(536 176)" fill="none" stroke={INK} strokeWidth="1.5" opacity=".8">
        <rect x="-9" y="-6" width="18" height="14" /><path d="M0 -6V-11" /><path d="M-4 0V2M4 0V2" strokeLinecap="square" /><path d="M-13 0V3M13 0V3" />
      </g>
      <text x="536" y="222" textAnchor="middle" {...lab} fill="rgba(11,16,21,.6)">YOUR AGENT&apos;S CONTEXT</text>
      <text x="536" y="241" textAnchor="middle" {...lab} fontSize="8" fill="rgba(11,16,21,.45)">OR</text>
      <g {...lab} fontSize="7.5" fill="rgba(11,16,21,.6)">
        <rect x="506.5" y="250.5" width="34" height="20" fill="#fff" stroke="rgba(11,16,21,.22)" /><text x="523.5" y="263" textAnchor="middle">MCP</text>
        <rect x="546.5" y="250.5" width="42" height="20" fill="#fff" stroke="rgba(11,16,21,.22)" /><text x="567.5" y="263" textAnchor="middle">HOOKS</text>
      </g>
      {/* comets */}
      {["c1", "c2", "c3", "c4", "c5"].map((k) => (
        <g key={k}>
          <path data-k={k} d="M0 0" fill="none" strokeWidth="2" strokeLinecap="square" opacity="0" stroke={GREEN} />
          <rect data-k={k + "h"} width="4" height="4" opacity="0" fill={GREEN} />
        </g>
      ))}
    </svg>
  );
}
