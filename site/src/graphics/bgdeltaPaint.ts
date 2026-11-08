import { BAYER4, fbm } from "./noise";
import { DH, DW } from "./deltaGeom";
import { GLOW, nearestChannel } from "./nearestChannel";

// Pixel work for the BgDelta backdrop. Pure (no DOM access), so it runs unchanged on an OffscreenCanvas in a worker
// (bgdelta.worker.ts) or on a detached <canvas> on the main thread (the fallback in BgDelta.tsx).
const CELL = 5;          // device-independent px per dither cell
const LEVELS = 10;       // land-dot alpha buckets (batched fills instead of one fillStyle per dot)
const G = "10,122,75";

export const MAX_DPR = 2;
/** Horizontal alpha mask baked into the bitmap: [position 0..1 across the width, alpha 0..1], ascending. */
export type MaskStops = [number, number][];
type Ctx = CanvasRenderingContext2D | OffscreenCanvasRenderingContext2D;

export function paintBackdrop(ctx: Ctx, w: number, h: number, dpr: number, stops: MaskStops | null) {
  ctx.scale(dpr, dpr);
  const sc = w / DW;
  const yOff = (DH * sc - h) / 2 / sc; // centre the delta vertically
  const cols = Math.ceil(w / CELL), rows = Math.ceil(h / CELL);
  const water: number[] = [];
  const land: number[][] = Array.from({ length: LEVELS }, () => []);
  for (let j = 0; j < rows; j++) for (let i = 0; i < cols; i++) {
    const sd = nearestChannel(((i + 0.5) * CELL) / sc, ((j + 0.5) * CELL) / sc + yOff);
    if (sd < 0.5) { water.push(i, j); continue; }
    const nx = i * 0.06, ny = j * 0.11;
    let v = 0.1 + 0.55 * fbm(nx, ny, 3, 3) + 0.12 * Math.sin((nx + ny * 0.6) * 3.1 + fbm(nx * 2, ny * 2, 9, 2) * 4);
    const bank = Math.max(0, 1 - sd / GLOW);
    v += 0.32 * bank * bank;
    v = Math.min(1, Math.max(0, v));
    if (v <= BAYER4[(j & 3) * 4 + (i & 3)] * 0.72 + 0.08) continue;
    land[Math.min(LEVELS - 1, Math.floor(v * LEVELS))].push(i, j);
  }
  const fill = (cells: number[], size: number) => {
    const o = (CELL - size) / 2;
    ctx.beginPath();
    for (let k = 0; k < cells.length; k += 2) ctx.rect(cells[k] * CELL + o, cells[k + 1] * CELL + o, size, size);
    ctx.fill();
  };
  for (let L = 0; L < LEVELS; L++) {
    const v = (L + 0.5) / LEVELS; // bucket centre
    ctx.fillStyle = `rgba(${G},${(0.03 + 0.11 * v).toFixed(3)})`;
    fill(land[L], CELL * 0.4);
  }
  ctx.fillStyle = `rgba(${G},.30)`;
  fill(water, CELL * 0.62);
  if (stops) {
    // Bake the mask: keep the dots in proportion to the gradient's alpha (what a CSS mask-image would do).
    const g = ctx.createLinearGradient(0, 0, w, 0);
    for (const [at, a] of stops) g.addColorStop(at, `rgba(0,0,0,${a})`);
    ctx.globalCompositeOperation = "destination-in";
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, w, h);
  }
}
