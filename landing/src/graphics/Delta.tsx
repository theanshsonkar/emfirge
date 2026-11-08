"use client";
import { useCallback, useRef } from "react";
import { BAYER4, fbm } from "./noise";
import { useCanvas, type DrawFn } from "./useCanvas";

// A generated dithered river delta. Design space is 640x266 and scales with the canvas.
// Channels are Catmull-Rom splines; land is layered value noise, ordered-dithered into fine dots.
type P = [number, number];
const DW = 640, DH = 266;

function spline(pts: P[], step = 3): P[] {
  const out: P[] = [];
  const g = (i: number) => pts[Math.max(0, Math.min(pts.length - 1, i))];
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = g(i - 1), p1 = g(i), p2 = g(i + 1), p3 = g(i + 2);
    const len = Math.hypot(p2[0] - p1[0], p2[1] - p1[1]);
    const n = Math.max(2, Math.round(len / step));
    for (let k = 0; k < n; k++) {
      const t = k / n, t2 = t * t, t3 = t2 * t;
      out.push([
        0.5 * (2 * p1[0] + (-p0[0] + p2[0]) * t + (2 * p0[0] - 5 * p1[0] + 4 * p2[0] - p3[0]) * t2 + (-p0[0] + 3 * p1[0] - 3 * p2[0] + p3[0]) * t3),
        0.5 * (2 * p1[1] + (-p0[1] + p2[1]) * t + (2 * p0[1] - 5 * p1[1] + 4 * p2[1] - p3[1]) * t2 + (-p0[1] + 3 * p1[1] - 3 * p2[1] + p3[1]) * t3),
      ]);
    }
  }
  out.push(pts[pts.length - 1]);
  return out;
}
const join = (...a: P[][]) => a.flat();

const TRUNK: P[] = [[-20, 140], [80, 130], [150, 144], [215, 136]];
const A: P[] = [[215, 136], [270, 112], [330, 86], [400, 72], [470, 66]];
const A1: P[] = [[470, 66], [560, 52], [660, 38]];
const A2: P[] = [[470, 66], [540, 88], [660, 98]];
const B: P[] = [[215, 136], [265, 160], [330, 180], [400, 196], [470, 200]];
const B1: P[] = [[470, 200], [560, 214], [660, 228]];
const B2: P[] = [[470, 200], [540, 176], [660, 170]];
const CREEKS: { pts: P[]; w: number }[] = [
  { pts: [[330, 86], [368, 44], [410, 6], [430, -10]], w: 1.4 },
  { pts: [[330, 180], [378, 224], [418, 262], [430, 280]], w: 1.4 },
  { pts: [[150, 144], [172, 190], [188, 240], [196, 280]], w: 1.2 },
  { pts: [[80, 130], [110, 90], [130, 40], [128, -10]], w: 1.2 },
  { pts: [[560, 52], [590, 70], [640, 80]], w: 1.1 },
  { pts: [[560, 214], [590, 196], [640, 192]], w: 1.1 },
];
const SEGS: { pts: P[]; w: number }[] = [
  { pts: spline(TRUNK), w: 4.2 },
  { pts: spline(A), w: 3.2 }, { pts: spline(B), w: 3.2 },
  { pts: spline(A1), w: 2.2 }, { pts: spline(A2), w: 2.2 },
  { pts: spline(B1), w: 2.2 }, { pts: spline(B2), w: 2.2 },
  ...CREEKS.map((c) => ({ pts: spline(c.pts), w: c.w })),
];
const PATHS = {
  A1: spline(join(TRUNK, A.slice(1), A1.slice(1)), 2),
  A2: spline(join(TRUNK, A.slice(1), A2.slice(1)), 2),
  B1: spline(join(TRUNK, B.slice(1), B1.slice(1)), 2),
  B2: spline(join(TRUNK, B.slice(1), B2.slice(1)), 2),
};
type PathName = keyof typeof PATHS;
const cum = (pts: P[]) => { const c = [0]; for (let i = 1; i < pts.length; i++) c.push(c[i - 1] + Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1])); return c; };
const LEN: Record<PathName, number[]> = { A1: cum(PATHS.A1), A2: cum(PATHS.A2), B1: cum(PATHS.B1), B2: cum(PATHS.B2) };
function at(name: PathName, f: number): P {
  const pts = PATHS[name], c = LEN[name], d = f * c[c.length - 1];
  let i = 1; while (i < c.length - 1 && c[i] < d) i++;
  const k = (d - c[i - 1]) / Math.max(1e-6, c[i] - c[i - 1]);
  return [pts[i - 1][0] + (pts[i][0] - pts[i - 1][0]) * k, pts[i - 1][1] + (pts[i][1] - pts[i - 1][1]) * k];
}

const hex = (h: string): [number, number, number] => [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)];
const mix = (a: [number, number, number], b: [number, number, number], t: number) => `rgb(${Math.round(a[0] + (b[0] - a[0]) * t)},${Math.round(a[1] + (b[1] - a[1]) * t)},${Math.round(a[2] + (b[2] - a[2]) * t)})`;

export type DeltaOpts = { field: string; lo: string; hi: string; drift: number; squares: boolean; cell?: number };

const CYCLE = 9, DUR = 4.4, LEVELS = 7;

export function Delta({ opts, className }: { opts: DeltaOpts; className?: string }) {
  const cache = useRef<{ key: string; cols: number; rows: number; water: Float32Array; bank: Float32Array } | null>(null);

  const draw: DrawFn = useCallback((ctx, w, h, t, still) => {
    const cell = (opts.cell ?? 4) * (w < 420 ? 0.75 : 1);
    const cols = Math.ceil(w / cell), rows = Math.ceil(h / cell);
    const key = `${cols}x${rows}`;
    const sc = w / DW;
    if (!cache.current || cache.current.key !== key) {
      const water = new Float32Array(cols * rows), bank = new Float32Array(cols * rows);
      const pts: [number, number, number][] = [];
      for (const s of SEGS) s.pts.forEach((p, i, a) => { const k = i / (a.length - 1); pts.push([p[0], p[1], s.w * (1 - 0.25 * k)]); });
      for (let j = 0; j < rows; j++) for (let i = 0; i < cols; i++) {
        const x = ((i + 0.5) * cell) / sc, y = ((j + 0.5) * cell) / sc;
        let sd = 1e9;
        for (const p of pts) { const d = Math.hypot(p[0] - x, p[1] - y) - p[2]; if (d < sd) sd = d; }
        water[j * cols + i] = sd; // signed distance in design px
      }
      cache.current = { key, cols, rows, water, bank };
    }
    const { water } = cache.current;
    const field = hex(opts.field), lo = hex(opts.lo), hi = hex(opts.hi);
    ctx.fillStyle = opts.field;
    ctx.fillRect(0, 0, w, h);
    const buckets: number[][] = Array.from({ length: LEVELS }, () => []);
    const big: number[] = [];
    const off = still ? 0 : t * opts.drift;
    for (let j = 0; j < rows; j++) for (let i = 0; i < cols; i++) {
      const sd = water[j * cols + i];
      if (sd < 0.5) { big.push(i, j); continue; }
      const nx = (i + off) * 0.06, ny = j * 0.11;
      let v = 0.1 + 0.55 * fbm(nx, ny, 3, 3) + 0.12 * Math.sin((nx + ny * 0.6) * 3.1 + fbm(nx * 2, ny * 2, 9, 2) * 4);
      const bankGlow = Math.max(0, 1 - sd / 11);
      v += 0.32 * bankGlow * bankGlow;
      v = Math.min(1, Math.max(0, v));
      const th = BAYER4[(j & 3) * 4 + (i & 3)] * 0.72 + 0.08;
      if (v <= th) continue;
      buckets[Math.min(LEVELS - 1, Math.floor(v * LEVELS))].push(i, j);
    }
    const sz = Math.max(1.2, cell * 0.46);
    for (let L = 0; L < LEVELS; L++) {
      ctx.fillStyle = mix(lo, hi, (L / (LEVELS - 1)) * 0.55 + 0.0);
      ctx.globalAlpha = 0.45 + 0.55 * (L / (LEVELS - 1));
      const b = buckets[L];
      ctx.beginPath();
      for (let k = 0; k < b.length; k += 2) ctx.rect(b[k] * cell + (cell - sz) / 2, b[k + 1] * cell + (cell - sz) / 2, sz, sz);
      ctx.fill();
    }
    ctx.globalAlpha = 1;
    ctx.fillStyle = mix(lo, hi, 0.95);
    const bs = sz * 1.45;
    ctx.beginPath();
    for (let k = 0; k < big.length; k += 2) ctx.rect(big[k] * cell + (cell - bs) / 2, big[k + 1] * cell + (cell - bs) / 2, bs, bs);
    ctx.fill();

    if (!opts.squares) return;
    const S = 14 * sc;
    const sq = (x: number, y: number, alpha: number, red: number) => {
      if (alpha <= 0.01) return;
      ctx.globalAlpha = alpha;
      ctx.fillStyle = red > 0 ? mix(hex("#E9F7EF"), hex("#C4574A"), red) : "#E9F7EF";
      ctx.fillRect(x * sc - S / 2, y * sc - S / 2, S, S);
      ctx.strokeStyle = red > 0 ? mix(hex("#7fbf9f"), hex("#8f2f26"), red) : "#7fbf9f";
      ctx.lineWidth = 1;
      ctx.strokeRect(x * sc - S / 2 + 0.5, y * sc - S / 2 + 0.5, S - 1, S - 1);
      ctx.globalAlpha = 1;
    };
    if (still) { const p = at("A1", 0.4); sq(p[0], p[1], 1, 0); return; }
    const n = Math.floor(t / CYCLE), tt = t - n * CYCLE, blocked = n % 2 === 1;
    const BLOCK_AT = 0.6;
    for (let i = 0; i < 3; i++) {
      const lt = tt - i * 1.5;
      if (lt < 0 || lt > DUR) continue;
      const f0 = lt / DUR;
      const ease = f0 < 0.5 ? 2 * f0 * f0 : 1 - Math.pow(-2 * f0 + 2, 2) / 2;
      const f = 0.04 + 0.92 * (0.35 * f0 + 0.65 * ease);
      let name: PathName = i === 0 ? "A1" : i === 1 ? "B1" : "A2";
      if (blocked) name = i === 0 ? "A1" : i === 1 ? "B1" : "B2";
      const fade = Math.min(1, lt / 0.4, (DUR - lt) / 0.4);
      if (blocked && i === 0) {
        const fb = BLOCK_AT;
        const reachT = DUR * 0.62; // time the square reaches the block point
        const p = at("A1", Math.min(f, fb));
        if (lt < reachT) { sq(p[0], p[1], fade, 0); }
        else {
          const r = lt - reachT;
          const bp = at("A1", fb);
          const redv = Math.min(1, r / 0.35), a = Math.max(0, 1 - Math.max(0, r - 0.7) / 0.9);
          sq(bp[0], bp[1], a, redv);
          // the block mark across the channel
          ctx.globalAlpha = a * redv; ctx.strokeStyle = "#C4574A"; ctx.lineWidth = 1.5;
          const nb = at("A1", fb + 0.01), pb = at("A1", fb - 0.01);
          const dx = nb[0] - pb[0], dy = nb[1] - pb[1], m = Math.hypot(dx, dy) || 1, nx = -dy / m, ny = dx / m, hl = 13;
          ctx.beginPath(); ctx.moveTo((bp[0] + nx * hl) * sc, (bp[1] + ny * hl) * sc); ctx.lineTo((bp[0] - nx * hl) * sc, (bp[1] - ny * hl) * sc); ctx.stroke();
          ctx.globalAlpha = 1;
        }
        continue;
      }
      const p = at(name, f);
      sq(p[0], p[1], fade, 0);
    }
  }, [opts]);

  const ref = useCanvas(draw, { fps: 30 });
  return <canvas ref={ref} className={className ?? "cv"} aria-hidden="true" />;
}

export const HERO_DELTA: DeltaOpts = { field: "#0B3B2A", lo: "#2E8F64", hi: "#B9EBD2", drift: 0.6, squares: true };
export const CTA_DELTA: DeltaOpts = { field: "#0B1015", lo: "#1b3a2e", hi: "#4a9672", drift: 0.3, squares: false };
