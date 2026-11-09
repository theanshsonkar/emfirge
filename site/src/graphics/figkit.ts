"use client";
import { useEffect, type RefObject } from "react";

// Shared pieces for the timeline-driven figures (Figure 1's helpers, reused): comet geometry and a loop hook
// that runs apply(t, loopIndex) with the same rules as Figure 1: pause offscreen or in a hidden tab, and under
// reduced motion draw the final state once (still()).
export type Pt = [number, number];
export const INK = "#0B1015", GREEN = "#0A7A4B", RED = "#C4574A", RED_D = "#B5483B";
export const MUTED = "rgba(11,16,21,.68)", EDGE = "rgba(11,16,21,.22)", SOFT = "rgba(11,16,21,.1)";
export const lab = { fontFamily: "var(--font-geist-mono), monospace", fontSize: 11, letterSpacing: 0.5, fontWeight: 500 } as const;
export const dotted = { stroke: "rgba(11,16,21,.38)", strokeWidth: 1, strokeDasharray: "1 3", fill: "none" } as const;
export const clamp = (x: number, a = 0, b = 1) => Math.min(b, Math.max(a, x));
export const ramp = (t: number, a: number, b: number) => clamp((t - a) / (b - a));
export const ease = (x: number) => 1 - Math.pow(1 - x, 3);
export const plen = (p: Pt[]) => p.slice(1).reduce((s, q, i) => s + Math.hypot(q[0] - p[i][0], q[1] - p[i][1]), 0);
export function pointAt(p: Pt[], d: number): Pt {
  let rem = d;
  for (let i = 1; i < p.length; i++) {
    const l = Math.hypot(p[i][0] - p[i - 1][0], p[i][1] - p[i - 1][1]);
    if (rem <= l || i === p.length - 1) { const k = clamp(rem / (l || 1)); return [p[i - 1][0] + (p[i][0] - p[i - 1][0]) * k, p[i - 1][1] + (p[i][1] - p[i - 1][1]) * k]; }
    rem -= l;
  }
  return p[p.length - 1];
}
export function cometD(p: Pt[], head: number, tail = 34): string {
  const L = plen(p), h = clamp(head) * L, s = Math.max(0, h - tail);
  const pts: Pt[] = [pointAt(p, s)];
  let acc = 0;
  for (let i = 1; i < p.length; i++) { acc += Math.hypot(p[i][0] - p[i - 1][0], p[i][1] - p[i - 1][1]); if (acc > s && acc < h) pts.push(p[i]); }
  pts.push(pointAt(p, h));
  return "M" + pts.map((q) => q.map((n) => n.toFixed(1)).join(" ")).join("L");
}
export const seg = (p: Pt[]) => "M" + p.map((q) => q.join(" ")).join("L");

/** Draw one comet (path + 4px head) on path p while t is inside [a, b]. */
export function comet(path: SVGElement, head: SVGElement, p: Pt[], a: number, b: number, t: number, color: string, tail = 34) {
  const f = ramp(t, a, b);
  if (f <= 0 || f >= 1) { path.setAttribute("opacity", "0"); head.setAttribute("opacity", "0"); return; }
  const o = String(Math.min(1, f * 6, (1 - f) * 6));
  path.setAttribute("d", cometD(p, ease(f), tail));
  path.setAttribute("stroke", color);
  path.setAttribute("opacity", o);
  const pt = pointAt(p, ease(f) * plen(p));
  head.setAttribute("x", String(pt[0] - 2)); head.setAttribute("y", String(pt[1] - 2));
  head.setAttribute("fill", color);
  head.setAttribute("opacity", o);
}

export function useTimeline(root: RefObject<SVGSVGElement | null>, T: number, speed: number, apply: (t: number, loop: number) => void, still: () => void, deps: unknown[]) {
  useEffect(() => {
    const svg = root.current!;
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    let raf = 0, visible = false, start = performance.now(), running = false, paused = 0;
    const frame = (now: number) => {
      raf = 0; if (!running) return;
      const sec = ((now - start) / 1000) * speed;
      apply(sec % T, Math.floor(sec / T));
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}
