"use client";
import { useCallback, useRef } from "react";
import { add, box, edge, faceColor, fit, proj, rasterQuads, type Dot, type Quad, type V3 } from "./dots";
import { useCanvas, type DrawFn } from "./useCanvas";

// Figure 2: a base slab with thin translucent change layers; a fork splits a second stack off. One 9s loop, final state under reduced motion.
const base = (x: number, y: number, g: number) => box(x, y, 0, 10, 10, 1.4, g, { top: (u, v) => (edge(u, v, 0.05) ? 1 : 0.55), left: (u, v) => (edge(u, v, 0.1) ? 1 : 0.7), right: (u, v) => (edge(u, v, 0.1) ? 1 : 0.7) });
const layer = (x: number, y: number, z: number, g: number) => box(x + 0.6, y + 0.6, z, 8.8, 8.8, 0.35, g, { top: (u, v) => (edge(u, v, 0.05) ? 1 : 0.3), left: () => 1, right: () => 1 });
const FX = 13, FY = -13; // the fork's world offset: slides right along the iso axis
const GROUPS: { quads: Quad[]; z: number; fork: boolean; label?: string }[] = [
  { quads: base(0, 0, 0), z: 0, fork: false, label: "base" },
  { quads: layer(0, 0, 3.6, 1), z: 3.6, fork: false, label: "change 1" },
  { quads: layer(0, 0, 6.4, 2), z: 6.4, fork: false, label: "change 2" },
  { quads: base(FX, FY, 3), z: 0, fork: true },
  { quads: layer(FX, FY, 3.6, 4), z: 3.6, fork: true },
  { quads: layer(FX, FY, 6.4, 5), z: 6.4, fork: true },
  { quads: layer(FX, FY, 9.2, 6), z: 9.2, fork: true, label: "change 3" },
];
const T = 9;
const cl = (x: number) => Math.min(1, Math.max(0, x));
const ez = (x: number) => 1 - Math.pow(1 - cl(x), 3);

type Fit = { s: number; ox: number; oy: number };
const bounds = (quads: Quad[]) => {
  const pts: [number, number][] = [];
  quads.forEach((q) => [q.o, add(q.o, q.a), add(q.o, q.b), add(add(q.o, q.a), q.b)].forEach((p) => pts.push(proj(p))));
  const xs = pts.map((p) => p[0]), ys = pts.map((p) => p[1]);
  return { minX: Math.min(...xs), maxX: Math.max(...xs), minY: Math.min(...ys), maxY: Math.max(...ys) };
};
const place = (quads: Quad[], s: number, cx: number, cy: number): Fit => {
  const b = bounds(quads);
  return { s, ox: cx - ((b.minX + b.maxX) / 2) * s, oy: cy - ((b.minY + b.maxY) / 2) * s };
};
const BASE_Q = GROUPS.slice(0, 3).flatMap((g) => g.quads), FORK_Q = GROUPS.slice(3).flatMap((g) => g.quads);

export function BranchFig() {
  const cache = useRef<{ key: string; dots: Dot[][]; fa: Fit; fb: Fit; pitch: number; tall: boolean } | null>(null);
  const draw = useCallback<DrawFn>((ctx, w, h, t0, still) => {
    // Phones: the base stack on top and the fork stack under it, labels inside the frame. Wider: side by side along the iso axis.
    const tall = w < 560;
    const pitch = w < 420 ? 3.4 : 4.4;
    const key = `${w}x${h}`;
    if (!cache.current || cache.current.key !== key) {
      let fa: Fit, fb: Fit;
      if (tall) {
        const lw = 92, rw = w - lw - 10; // room for the leader and label on the open side of each stack
        const bA = bounds(BASE_Q), bB = bounds(FORK_Q);
        const s = Math.min((rw * 0.94) / (bA.maxX - bA.minX), (rw * 0.94) / (bB.maxX - bB.minX), (h * 0.46) / (bA.maxY - bA.minY), (h * 0.46) / (bB.maxY - bB.minY));
        fa = place(BASE_Q, s, w - 8 - rw / 2 - 4, h * 0.27);
        fb = place(FORK_Q, s, 8 + rw / 2 + 4, h * 0.74);
      } else {
        const f = fit(GROUPS.flatMap((g) => g.quads), w * 0.66, h, 0.94);
        fa = fb = { s: f.s, ox: f.ox + w * 0.2, oy: f.oy };
      }
      cache.current = { key, fa, fb, pitch, tall, dots: GROUPS.map((g) => { const f = g.fork ? fb : fa; return rasterQuads(g.quads, f.s, f.ox, f.oy, pitch, w, h); }) };
    }
    const { dots, fa, fb } = cache.current;
    const t = still ? 8 : t0 % T;
    const spf = (f: Fit, p: V3): [number, number] => { const q = proj(p); return [q[0] * f.s + f.ox, q[1] * f.s + f.oy]; };
    const snap = (n: number) => Math.round(n / pitch) * pitch;
    ctx.clearRect(0, 0, w, h);
    const fadeAll = still ? 1 : 1 - ez((t - 8.3) / 0.6);
    // fork connector (thin dotted line between the two slabs)
    const a = spf(fa, [5, 5, 0.7]), b = spf(fb, [FX + 5, FY + 5, 0.7]);
    const conn = still ? 1 : ez((t - 3.6) / 0.6) * fadeAll;
    if (conn > 0.02) {
      ctx.strokeStyle = `rgba(10,122,75,${0.55 * conn})`; ctx.lineWidth = 1; ctx.setLineDash([2, 4]);
      ctx.beginPath(); ctx.moveTo(a[0], a[1] + 8); ctx.lineTo(a[0] + (b[0] - a[0]) * conn, a[1] + 8 + (b[1] - a[1]) * conn); ctx.stroke(); ctx.setLineDash([]);
    }
    GROUPS.forEach((g, gi) => {
      let alpha = 1, dy = 0, dx = 0;
      const i = gi;
      const sc = (g.fork ? fb : fa).s;
      if (!still) {
        if (g.fork) {
          const k = ez((t - 3 - (i - 3) * 0.1) / 1.2);
          alpha = k; dx = -(1 - k) * (b[0] - a[0]); dy = -(1 - k) * (b[1] - a[1]);
          if (i === 6) { const d = ez((t - 4.8) / 0.7); alpha = d * (t > 4.7 ? 1 : 0); dx = 0; dy = -(1 - d) * 5 * sc * 0.9; }
        } else if (i === 1 || i === 2) {
          const d = ez((t - (i === 1 ? 0.5 : 1.4)) / 0.7);
          alpha = d; dy = -(1 - d) * 5 * sc * 0.9;
        }
      }
      alpha *= g.fork || gi > 0 ? fadeAll : 1;
      if (g.fork === false && gi === 0) alpha = 1;
      if (alpha <= 0.02) return;
      const tx = snap(dx), ty = snap(dy);
      for (const d of dots[gi]) {
        const q = g.quads[d.q];
        const k = q.pat ? q.pat(d.u, d.v, t) : 0.6;
        if (k <= 0.04) continue;
        const aa = (0.5 + 0.5 * q.shade) * Math.max(k, 0.25) * alpha * (gi === 0 || gi === 3 ? 1 : 0.85);
        const size = 1.6 + 1.3 * Math.min(1, aa);
        ctx.fillStyle = faceColor(q.shade, aa);
        ctx.fillRect(d.x + tx - size / 2, d.y + ty - size / 2, size, size);
      }
    });
    // labels with leader lines
    ctx.font = `500 11px ${getComputedStyle(document.documentElement).getPropertyValue("--font-geist-mono") || "monospace"}`;
    ctx.textBaseline = "middle";
    GROUPS.forEach((g, gi) => {
      if (!g.label) return;
      let vis = 1;
      if (!still) {
        if (gi === 1) vis = ez((t - 1.1) / 0.4); else if (gi === 2) vis = ez((t - 2) / 0.4); else if (gi === 6) vis = ez((t - 5.4) / 0.4); else if (gi === 0) vis = 1;
        if (gi !== 0) vis *= fadeAll;
      }
      if (vis <= 0.02) return;
      const fork = g.fork;
      // the layer's left corner (or right corner for the fork), a short leader, then the label
      const p = spf(fork ? fb : fa, fork ? [FX + 10, FY, g.z + 0.15] : [0, 10, g.z + (gi === 0 ? 0.7 : 0.15)]);
      const lx = fork ? p[0] + 26 : p[0] - 26, ly = p[1];
      ctx.strokeStyle = `rgba(11,16,21,${0.35 * vis})`; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(p[0] + (fork ? 4 : -4), p[1]); ctx.lineTo(lx, ly); ctx.stroke();
      ctx.fillStyle = `rgba(11,16,21,${0.72 * vis})`;
      ctx.textAlign = fork ? "left" : "right";
      ctx.fillText(g.label!.toUpperCase(), lx + (fork ? 5 : -5), ly);
    });
    if (still || t > 3.9) {
      const vis = (still ? 1 : ez((t - 3.9) / 0.4)) * fadeAll;
      const p = spf(fb, [FX + 10, FY, 0.7]);
      ctx.fillStyle = `rgba(10,122,75,${0.95 * vis})`; ctx.textAlign = "left";
      ctx.fillText("FORK", p[0] + 10, p[1] + 8);
    }
  }, []);
  const ref = useCanvas(draw, { fps: 24 });
  return <canvas ref={ref} className="cv" role="img" aria-label="A base slab with change layers stacked on it, and a fork splitting a second stack off" />;
}
export default BranchFig;
