"use client";
import { useCallback, useRef } from "react";
import { BAYER4, fbm } from "./noise";
import { useCanvas, type DrawFn } from "./useCanvas";
import { DW, at, hex, mix, type PathName } from "./deltaGeom";
import { GLOW, nearestChannel } from "./nearestChannel";

// A generated dithered river delta. Design space is 640x266 and scales with the canvas.
// Channels are Catmull-Rom splines (deltaGeom.ts); land is layered value noise, ordered-dithered into fine dots.
export type DeltaOpts = { field: string; lo: string; hi: string; drift: number; squares: boolean; cell?: number; yOff?: number };

const CYCLE = 9, DUR = 4.4, LEVELS = 7;
const SENTINEL = 0.5; // lineDashOffset is never used here, so it is free to mark "this canvas still holds our last frame"
const LAND_MS = 150; // the dither layer drifts at <1 cell/s, so it is re-rendered at ~7Hz and blitted in between

type Ctx2D = CanvasRenderingContext2D;
type Layer = { cv: HTMLCanvasElement; ctx: CanvasRenderingContext2D };
type Cache = {
  key: string; opts: DeltaOpts; cols: number; rows: number; cell: number;
  water: Float32Array;  // signed distance per cell, design px
  big: Int32Array;      // (i, j) pairs of the water cells, drawn as the larger squares
  waterL: Layer | null; // static water squares at device resolution (transparent background); null until first animated frame
  landL: Layer | null;  // opaque composite of field + dithered land + water, re-rendered every LAND_MS
  landAt: number;       // ms timestamp of the last land render
  box: [number, number, number, number] | null; // device-px bbox of the moving squares painted on the visible canvas last frame
};

function makeLayer(pw: number, ph: number, w: number, h: number): Layer | null {
  // A detached <canvas>, not OffscreenCanvas: blitting from it onto the visible canvas measured markedly cheaper.
  const cv = Object.assign(document.createElement("canvas"), { width: pw, height: ph });
  const ctx = cv.getContext("2d");
  if (!ctx) return null;
  ctx.setTransform(pw / w, 0, 0, ph / h, 0, 0); // same CSS-px -> device-px mapping as the visible canvas
  return { cv, ctx };
}

export function Delta({ opts, className }: { opts: DeltaOpts; className?: string }) {
  const cache = useRef<Cache | null>(null);

  const draw: DrawFn = useCallback((ctx, w, h, t, still) => {
    const cell = (opts.cell ?? 4) * (w < 420 ? 0.75 : 1);
    const cols = Math.ceil(w / cell), rows = Math.ceil(h / cell);
    const pw = ctx.canvas.width, ph = ctx.canvas.height;
    const key = `${cols}x${rows}:${opts.yOff ?? 0}:${pw}x${ph}`;
    const sc = w / DW;
    let c = cache.current;
    if (!c || c.key !== key || c.opts !== opts) {
      const water = new Float32Array(cols * rows);
      const big: number[] = [];
      for (let j = 0; j < rows; j++) for (let i = 0; i < cols; i++) {
        const x = ((i + 0.5) * cell) / sc, y = ((j + 0.5) * cell) / sc + (opts.yOff ?? 0);
        const sd = nearestChannel(x, y); // signed distance in design px, capped at GLOW (beyond it only "not water, no bank glow" matters)
        water[j * cols + i] = sd;
        if (sd < 0.5) big.push(i, j);
      }
      c = cache.current = { key, opts, cols, rows, cell, water, big: Int32Array.from(big), waterL: null, landL: null, landAt: -Infinity, box: null };
    }
    const lo = hex(opts.lo), hi = hex(opts.hi);
    const sz = Math.max(1.2, cell * 0.46);

    // The dithered land: layered noise, ordered-dithered, bucketed by brightness level.
    const paintLand = (g: Ctx2D, off: number) => {
      const buckets: number[][] = Array.from({ length: LEVELS }, () => []);
      const { water } = c;
      for (let j = 0; j < rows; j++) for (let i = 0; i < cols; i++) {
        const sd = water[j * cols + i];
        if (sd < 0.5) continue;
        const nx = (i + off) * 0.06, ny = j * 0.11;
        let v = 0.1 + 0.55 * fbm(nx, ny, 3, 3) + 0.12 * Math.sin((nx + ny * 0.6) * 3.1 + fbm(nx * 2, ny * 2, 9, 2) * 4);
        const bankGlow = Math.max(0, 1 - sd / GLOW);
        v += 0.32 * bankGlow * bankGlow;
        v = Math.min(1, Math.max(0, v));
        const th = BAYER4[(j & 3) * 4 + (i & 3)] * 0.72 + 0.08;
        if (v <= th) continue;
        buckets[Math.min(LEVELS - 1, Math.floor(v * LEVELS))].push(i, j);
      }
      for (let L = 0; L < LEVELS; L++) {
        g.fillStyle = mix(lo, hi, (L / (LEVELS - 1)) * 0.55 + 0.0);
        g.globalAlpha = 0.45 + 0.55 * (L / (LEVELS - 1));
        const b = buckets[L];
        g.beginPath();
        for (let k = 0; k < b.length; k += 2) g.rect(b[k] * cell + (cell - sz) / 2, b[k + 1] * cell + (cell - sz) / 2, sz, sz);
        g.fill();
      }
      g.globalAlpha = 1;
    };
    // The static water squares (they only depend on size and yOff).
    const paintWater = (g: Ctx2D) => {
      g.fillStyle = mix(lo, hi, 0.95);
      const bs = sz * 1.45, big = c.big;
      g.beginPath();
      for (let k = 0; k < big.length; k += 2) g.rect(big[k] * cell + (cell - bs) / 2, big[k + 1] * cell + (cell - bs) / 2, bs, bs);
      g.fill();
    };

    let landDirty = false;
    if (still) {
      ctx.lineDashOffset = 0;
      ctx.fillStyle = opts.field;
      ctx.fillRect(0, 0, w, h);
      // Reduced motion: one static frame, painted straight onto the canvas in the original order.
      paintLand(ctx, 0);
      paintWater(ctx);
    } else {
      // Animated: one blit of the cached field + land + water composite (land refreshed every LAND_MS), then the moving squares.
      const ms = t * 1000;
      if (!c.waterL) {
        c.waterL = makeLayer(pw, ph, w, h);
        if (c.waterL) paintWater(c.waterL.ctx);
      }
      if (!c.landL) c.landL = makeLayer(pw, ph, w, h);
      const L = c.landL;
      if (L && c.waterL && (ms - c.landAt >= LAND_MS || ms < c.landAt)) {
        landDirty = true;
        // Re-composite field + land + water into one opaque layer, in the original draw order, so a frame is a single blit.
        L.ctx.fillStyle = opts.field;
        L.ctx.fillRect(0, 0, w, h);
        paintLand(L.ctx, t * opts.drift);
        L.ctx.save();
        L.ctx.setTransform(1, 0, 0, 1, 0, 0);
        L.ctx.drawImage(c.waterL.cv, 0, 0);
        L.ctx.restore();
        c.landAt = ms;
      }
      if (L && c.waterL) {
        // The visible canvas only changes where the squares move, plus a full refresh whenever the land layer re-rendered.
        // useCanvas resets the context state whenever it resizes (and so clears) the canvas, so a sentinel in unused
        // state tells us the pixels we last drew are gone.
        const intact = ctx.lineDashOffset === SENTINEL;
        ctx.save();
        ctx.setTransform(1, 0, 0, 1, 0, 0); // layer is already at device resolution: 1:1 blit, no resampling
        if (!intact || landDirty) { ctx.drawImage(L.cv, 0, 0); c.box = null; }
        else if (c.box) { const [x, y, bw, bh] = c.box; ctx.drawImage(L.cv, x, y, bw, bh, x, y, bw, bh); c.box = null; } // erase last frame's squares
        ctx.restore();
        ctx.lineDashOffset = SENTINEL;
      } else { ctx.fillStyle = opts.field; ctx.fillRect(0, 0, w, h); paintLand(ctx, t * opts.drift); paintWater(ctx); } // no 2d context for the layers: fall back to the direct draw
    }

    if (!opts.squares) return;
    const S = 14 * sc;
    // CSS-px bbox of everything the moving squares paint this frame (padded for strokes/AA), so the next frame can erase just that.
    let bx0 = Infinity, by0 = Infinity, bx1 = -Infinity, by1 = -Infinity;
    const grow = (x0: number, y0: number, x1: number, y1: number) => { bx0 = Math.min(bx0, x0); by0 = Math.min(by0, y0); bx1 = Math.max(bx1, x1); by1 = Math.max(by1, y1); };
    const sq = (x: number, y: number, alpha: number, red: number) => {
      if (alpha <= 0.01) return;
      grow(x * sc - S / 2 - 2, y * sc - S / 2 - 2, x * sc + S / 2 + 2, y * sc + S / 2 + 2);
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
          grow(Math.min(bp[0] + nx * hl, bp[0] - nx * hl) * sc - 3, Math.min(bp[1] + ny * hl, bp[1] - ny * hl) * sc - 3, Math.max(bp[0] + nx * hl, bp[0] - nx * hl) * sc + 3, Math.max(bp[1] + ny * hl, bp[1] - ny * hl) * sc + 3);
          ctx.beginPath(); ctx.moveTo((bp[0] + nx * hl) * sc, (bp[1] + ny * hl) * sc); ctx.lineTo((bp[0] - nx * hl) * sc, (bp[1] - ny * hl) * sc); ctx.stroke();
          ctx.globalAlpha = 1;
        }
        continue;
      }
      const p = at(name, f);
      sq(p[0], p[1], fade, 0);
    }
    if (bx1 > bx0 && c.landL) {
      const kx = pw / w, ky = ph / h;
      const x0 = Math.max(0, Math.floor(bx0 * kx) - 1), y0 = Math.max(0, Math.floor(by0 * ky) - 1);
      const x1 = Math.min(pw, Math.ceil(bx1 * kx) + 1), y1 = Math.min(ph, Math.ceil(by1 * ky) + 1);
      if (x1 > x0 && y1 > y0) c.box = [x0, y0, x1 - x0, y1 - y0];
    }
  }, [opts]);

  const ref = useCanvas(draw, { fps: 30 });
  return <canvas ref={ref} className={className ?? "cv"} aria-hidden="true" />;
}

export const HERO_DELTA: DeltaOpts = { field: "#0B3B2A", lo: "#2E8F64", hi: "#B9EBD2", drift: 0.6, squares: true };
export const CTA_DELTA: DeltaOpts = { field: "#0B1015", lo: "#1b3a2e", hi: "#4a9672", drift: 0.3, squares: false };
export const PLAN_DELTA: DeltaOpts = { field: "#0B3B2A", lo: "#2E8F64", hi: "#B9EBD2", drift: 0.4, squares: false, yOff: 70 };
