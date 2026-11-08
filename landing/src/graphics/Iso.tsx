"use client";
import { useCallback, useRef } from "react";
import { useCanvas, type DrawFn } from "./useCanvas";
import { box, edge, faceColor, fit, rasterQuads, type Dot, type Quad } from "./dots";

// Dot-matrix isometric illustrations; the quad rasteriser lives in dots.ts.
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

export function Iso({ kind }: { kind: "laptop" | "pipeline" | "container" }) {
  const cache = useRef<{ key: string; dots: Dot[]; pitch: number } | null>(null);
  const draw = useCallback<DrawFn>((ctx, w, h, t, still) => {
    const quads = SCENES[kind];
    const pitch = w < 150 ? 3.6 : 4.4;
    const key = `${w}x${h}`;
    if (!cache.current || cache.current.key !== key) {
      const f = fit(quads, w, h);
      const dots = rasterQuads(quads, f.s, f.ox, f.oy, pitch, w, h);
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
      ctx.fillStyle = faceColor(q.shade, a);
      ctx.fillRect(d.x - size / 2, d.y - size / 2, size, size);
    }
  }, [kind]);
  const ref = useCanvas(draw, { fps: 20 });
  return <canvas ref={ref} className="cv" aria-hidden="true" />;
}
