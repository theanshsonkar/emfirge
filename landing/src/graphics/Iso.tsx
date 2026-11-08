"use client";
import { useCallback, useRef } from "react";
import { useCanvas, type DrawFn } from "./useCanvas";

// Dot-matrix isometric illustrations: parallelogram faces rasterised onto a fine dot grid.
type V3 = [number, number, number];
type Quad = { o: V3; a: V3; b: V3; shade: number; grp: number; pat?: (u: number, v: number, t: number) => number };

const proj = (p: V3): [number, number] => [(p[0] - p[1]) * 0.866, (p[0] + p[1]) * 0.5 - p[2]];
const add = (p: V3, q: V3, k = 1): V3 => [p[0] + q[0] * k, p[1] + q[1] * k, p[2] + q[2] * k];

function box(x: number, y: number, z: number, sx: number, sy: number, sz: number, grp: number, pats: { top?: Quad["pat"]; left?: Quad["pat"]; right?: Quad["pat"] } = {}): Quad[] {
  return [
    { o: [x, y, z + sz], a: [sx, 0, 0], b: [0, sy, 0], shade: 0.55, grp, pat: pats.top },
    { o: [x, y + sy, z], a: [sx, 0, 0], b: [0, 0, sz], shade: 1, grp, pat: pats.left },
    { o: [x + sx, y, z], a: [0, sy, 0], b: [0, 0, sz], shade: 0.78, grp, pat: pats.right },
  ];
}
const edge = (u: number, v: number, e: number) => u < e || v < e || u > 1 - e || v > 1 - e;

const SCENES: Record<string, Quad[]> = {
  laptop: [
    // screen first (behind), bezel + terminal
    {
      o: [0, 0, 0.7], a: [0, 8, 0], b: [-1.3, 0, 6.4], shade: 0.9, grp: 0,
      pat: (u, v, t) => {
        if (edge(u, v, 0.05)) return 1;
        const row = Math.floor(v * 11);
        if (row === 9 && u < 0.16) return 0.95; // prompt
        if (row === 9 && u > 0.2 && u < 0.24) return Math.floor(t * 1.2) % 2 === 0 ? 0.95 : 0.1; // cursor
        if (row > 1 && row < 9 && row % 2 === 0) { const len = 0.25 + 0.5 * ((row * 37) % 7) / 7; return u < len + 0.1 && u > 0.1 ? 0.7 : 0.12; }
        return 0.14;
      },
    },
    ...box(0, 0, 0, 10, 8, 0.7, 1, {
      top: (u, v) => (edge(u, v, 0.08) ? 1 : (Math.floor(u * 9) % 2 === 0 || Math.floor(v * 5) % 2 === 0 ? 0.28 : 0.85)),
    }),
  ],
  pipeline: [
    ...box(4.2, 1.7, 0, 4.6, 1, 0.3, 0),
    ...box(13, 1.7, 0, 4.6, 1, 0.3, 0),
    ...box(0, 0, 0, 4.4, 4.4, 4.4, 1, { top: (u, v) => (edge(u, v, 0.12) ? 1 : 0.45) }),
    ...box(8.8, 0, 0, 4.4, 4.4, 4.4, 2, { top: (u, v) => (edge(u, v, 0.12) ? 1 : 0.45) }),
    ...box(17.6, 0, 0, 4.4, 4.4, 4.4, 3, { top: (u, v) => (edge(u, v, 0.12) ? 1 : 0.45) }),
  ],
  container: [
    ...box(0, 0, 0, 7, 5, 5, 1, {
      left: (u, v) => (edge(u, v, 0.04) ? 1 : (Math.floor(u * 14) % 2 === 0 ? 1 : 0.4)),
      right: (u, v) => (edge(u, v, 0.05) || Math.abs(u - 0.5) < 0.03 ? 1 : (v > 0.4 && v < 0.6 && (Math.abs(u - 0.4) < 0.04 || Math.abs(u - 0.6) < 0.04) ? 1 : 0.5)),
      top: (u, v) => (edge(u, v, 0.05) ? 1 : (Math.floor(v * 10) % 2 === 0 ? 0.8 : 0.3)),
    }),
  ],
};
// the container is long: stretch x
SCENES.container = [
  ...box(0, 0, 0, 12, 5, 5, 1, {
    left: (u, v) => (edge(u, v, 0.03) ? 1 : (Math.floor(u * 24) % 2 === 0 ? 1 : 0.35)),
    right: (u, v) => (edge(u, v, 0.05) || Math.abs(u - 0.5) < 0.03 ? 1 : (v > 0.4 && v < 0.6 && (Math.abs(u - 0.4) < 0.05 || Math.abs(u - 0.6) < 0.05) ? 1 : 0.5)),
    top: (u, v) => (edge(u, v, 0.04) ? 1 : (Math.floor(u * 24) % 2 === 0 ? 0.8 : 0.3)),
  }),
];

type Dot = { x: number; y: number; q: number; u: number; v: number };
export function Iso({ kind }: { kind: "laptop" | "pipeline" | "container" }) {
  const cache = useRef<{ key: string; dots: Dot[]; pitch: number } | null>(null);
  const draw = useCallback<DrawFn>((ctx, w, h, t, still) => {
    const quads = SCENES[kind];
    const pitch = w < 150 ? 3.6 : 4.4;
    const key = `${w}x${h}`;
    if (!cache.current || cache.current.key !== key) {
      const pts: [number, number][] = [];
      quads.forEach((q) => { [q.o, add(q.o, q.a), add(q.o, q.b), add(add(q.o, q.a), q.b)].forEach((p) => pts.push(proj(p))); });
      const minX = Math.min(...pts.map((p) => p[0])), maxX = Math.max(...pts.map((p) => p[0]));
      const minY = Math.min(...pts.map((p) => p[1])), maxY = Math.max(...pts.map((p) => p[1]));
      const s = Math.min((w * 0.9) / (maxX - minX), (h * 0.9) / (maxY - minY));
      const ox = (w - (maxX - minX) * s) / 2 - minX * s, oy = (h - (maxY - minY) * s) / 2 - minY * s;
      const sp = (p: V3): [number, number] => { const q = proj(p); return [q[0] * s + ox, q[1] * s + oy]; };
      const dots: Dot[] = [];
      const cols = Math.floor(w / pitch), rows = Math.floor(h / pitch);
      for (let j = 0; j < rows; j++) for (let i = 0; i < cols; i++) {
        const x = (i + 0.5) * pitch, y = (j + 0.5) * pitch;
        for (let qi = quads.length - 1; qi >= 0; qi--) {
          const q = quads[qi];
          const P0 = sp(q.o), A = sp(add(q.o, q.a)), B = sp(add(q.o, q.b));
          const ax = A[0] - P0[0], ay = A[1] - P0[1], bx = B[0] - P0[0], by = B[1] - P0[1];
          const det = ax * by - ay * bx;
          if (Math.abs(det) < 1e-6) continue;
          const dx = x - P0[0], dy = y - P0[1];
          const u = (dx * by - dy * bx) / det, v = (ax * dy - ay * dx) / det;
          if (u >= -0.001 && u <= 1.001 && v >= -0.001 && v <= 1.001) {
            // painter's order: later quads draw on top, so the first hit from the end wins
            dots.push({ x, y, q: qi, u: Math.min(1, Math.max(0, u)), v: Math.min(1, Math.max(0, v)) });
            break;
          }
        }
      }
      cache.current = { key, dots, pitch };
    }
    const { dots } = cache.current;
    ctx.clearRect(0, 0, w, h);
    const sweep = still ? -10 : ((t * 0.07) % 1.6) * (w + h) - h * 0.3;
    const active = Math.floor(t / 1.4) % 4;
    for (const d of dots) {
      const q = quads[d.q];
      let k = q.pat ? q.pat(d.u, d.v, t) : 0.6;
      if (k <= 0.04) continue;
      let a = (0.55 + 0.45 * q.shade) * Math.max(k, 0.22);
      const sd = Math.abs(d.x + d.y * 0.6 - sweep) / 40;
      if (sd < 1) a = Math.min(1, a + 0.35 * (1 - sd));
      if (kind === "pipeline" && !still && q.grp > 0) a = a * (q.grp === 1 + (active % 3) ? 1.0 : 0.62);
      const size = 1.7 + 1.3 * Math.min(1, a);
      ctx.fillStyle = q.shade > 0.9 ? `rgba(10,122,75,${a})` : q.shade > 0.7 ? `rgba(32,150,100,${a})` : `rgba(90,190,148,${a})`;
      ctx.fillRect(d.x - size / 2, d.y - size / 2, size, size);
    }
  }, [kind]);
  const ref = useCanvas(draw, { fps: 20 });
  return <canvas ref={ref} className="cv" aria-hidden="true" />;
}
