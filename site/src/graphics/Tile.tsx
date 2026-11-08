"use client";
import { useCallback } from "react";
import { useCanvas, type DrawFn } from "./useCanvas";

// 80x80 animated dithered tiles: white dots on Emfirge green. One slow thing moves in each.
const N = 26;

function base(ctx: CanvasRenderingContext2D, w: number, h: number) {
  ctx.fillStyle = "#0A7A4B";
  ctx.fillRect(0, 0, w, h);
}
function dot(ctx: CanvasRenderingContext2D, w: number, i: number, j: number, a: number, color = "255,255,255", k = 0.5) {
  if (a <= 0.01) return;
  const c = w / N, s = c * k;
  ctx.fillStyle = `rgba(${color},${Math.min(1, a)})`;
  ctx.fillRect(i * c + (c - s) / 2, j * c + (c - s) / 2, s, s);
}
function grid(ctx: CanvasRenderingContext2D, w: number) {
  for (let j = 0; j < N; j++) for (let i = 0; i < N; i++) dot(ctx, w, i, j, 0.1, "255,255,255", 0.3);
}

const rings: DrawFn = (ctx, w, h, t) => {
  base(ctx, w, h); grid(ctx, w);
  const cells = new Map<number, number>();
  const put = (x: number, y: number, a: number) => {
    const i = Math.round(x), j = Math.round(y);
    if (i < 0 || j < 0 || i >= N || j >= N) return;
    const k = j * N + i; cells.set(k, Math.max(cells.get(k) ?? 0, a));
  };
  const rot = t * 0.22;
  const tilts = [0.5, 1.15, 1.8];
  tilts.forEach((tilt, r) => {
    const R = 9.6 - r * 0.9;
    for (let a = 0; a < 140; a++) {
      const ang = (a / 140) * Math.PI * 2;
      let x = Math.cos(ang) * R, y = Math.sin(ang) * R, z = 0;
      // tilt about X, then spin about Y
      const y1 = y * Math.cos(tilt) - z * Math.sin(tilt), z1 = y * Math.sin(tilt) + z * Math.cos(tilt);
      const ry = rot + r * 1.1;
      const x2 = x * Math.cos(ry) + z1 * Math.sin(ry), z2 = -x * Math.sin(ry) + z1 * Math.cos(ry);
      put(N / 2 - 0.5 + x2, N / 2 - 0.5 + y1, 0.55 + 0.45 * ((z2 / R + 1) / 2));
    }
  });
  cells.forEach((a, k) => dot(ctx, w, k % N, Math.floor(k / N), a, "255,255,255", 0.62));
};

// a trunk line that forks, a pulse travels it
const forkPts = (() => {
  const pts: [number, number][] = [];
  const add = (f: (u: number) => [number, number], n: number) => { for (let k = 0; k <= n; k++) pts.push(f(k / n)); };
  add((u) => [2 + u * 9, 13], 18);
  add((u) => [11 + u * 11, 13 - Math.sin(u * Math.PI * 0.5) * 8 - u * 1], 24);
  return pts;
})();
const forkB = (() => {
  const pts: [number, number][] = [];
  for (let k = 0; k <= 24; k++) { const u = k / 24; pts.push([11 + u * 11, 13 + Math.sin(u * Math.PI * 0.5) * 8 + u * 1]); }
  return pts;
})();
const fork: DrawFn = (ctx, w, h, t) => {
  base(ctx, w, h); grid(ctx, w);
  const p = ((t * 0.18) % 1.4);
  const draw = (pts: [number, number][], start: number, total: number) => {
    pts.forEach((pt, k) => {
      const pos = (start + k) / total;
      const d = Math.abs(pos - p / 1.0);
      const glow = Math.max(0, 1 - d / 0.16);
      dot(ctx, w, Math.round(pt[0]), Math.round(pt[1]), 0.5 + 0.5 * glow, "255,255,255", 0.6 + 0.3 * glow);
    });
  };
  // trunk 0..18 then branches 18..42
  draw(forkPts.slice(0, 19), 0, 42);
  draw(forkPts.slice(19), 18, 42);
  draw(forkB, 18, 42);
  // end caps
  [forkPts[forkPts.length - 1], forkB[forkB.length - 1]].forEach((e) => dot(ctx, w, Math.round(e[0]) + 1, Math.round(e[1]), 0.9, "255,255,255", 0.9));
};

const six: DrawFn = (ctx, w, h, t, still) => {
  base(ctx, w, h); grid(ctx, w);
  const cycle = 6.4;
  const k = still ? 4 : Math.floor(t / cycle) % 6;
  const lt = t % cycle;
  for (let q = 0; q < 6; q++) {
    const cx = 2 + (q % 3) * 8, cy = 5 + Math.floor(q / 3) * 9;
    let color = "255,255,255", a = 0.92;
    if (q === k && !still) {
      const flick = (x: number) => Math.floor(x / 0.14) % 2 === 0;
      if (lt > 1.2 && lt < 1.5) color = flick(lt) ? "232,105,90" : "255,255,255";
      else if (lt >= 1.5 && lt < 2.9) color = "232,105,90";
      else if (lt >= 2.9 && lt < 3.2) color = flick(lt) ? "255,255,255" : "232,105,90";
    }
    for (let j = 0; j < 6; j++) for (let i = 0; i < 6; i++) {
      const edge = i === 0 || j === 0 || i === 5 || j === 5;
      dot(ctx, w, cx + i, cy + j, edge ? a : a * 0.5, color, edge ? 0.7 : 0.5);
    }
  }
};

const KIND: Record<string, DrawFn> = { rings, fork, six };
export function Tile({ kind }: { kind: string }) {
  const d = useCallback<DrawFn>((c, w, h, t, s) => KIND[kind](c, w, h, t, s), [kind]);
  const ref = useCanvas(d, { fps: 24 });
  return <canvas ref={ref} className="cv" aria-hidden="true" />;
}
