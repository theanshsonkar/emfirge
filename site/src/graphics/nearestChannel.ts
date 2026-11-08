import { SEGS } from "./deltaGeom";

// Nearest-channel lookup for the dithered delta (Delta.tsx hero/CTA/plan canvases and the BgDelta backdrop).
// The signed distance to the channel set (design px, negative inside a channel) is only needed up to GLOW:
// past that a cell is "not water, no bank glow", so the result is capped there.
export const GLOW = 11;  // design px: how far a channel lights its banks
const GRID = 16;         // design px: spatial-grid cell, >= max channel radius (4.2) + GLOW so a 1-cell lookup is exact

type Pt = [number, number, number];

// Channel points bucketed into a coarse grid: each point is stored in every cell its influence box touches,
// so the lookup for a cell only has to scan that one cell's list instead of every SEGS point.
function build() {
  const pts: Pt[] = [];
  for (const s of SEGS) s.pts.forEach((p, i, a) => { const k = i / (a.length - 1); pts.push([p[0], p[1], s.w * (1 - 0.25 * k)]); });
  const cells = new Map<number, Pt[]>();
  const key = (gx: number, gy: number) => gx * 4096 + gy; // gy offset keeps keys unique for the ranges used here
  for (const p of pts) {
    const rr = p[2] + GLOW;
    for (let gx = Math.floor((p[0] - rr) / GRID); gx <= Math.floor((p[0] + rr) / GRID); gx++)
      for (let gy = Math.floor((p[1] - rr) / GRID); gy <= Math.floor((p[1] + rr) / GRID); gy++) {
        const k = key(gx, gy + 1024);
        const l = cells.get(k);
        if (l) l.push(p); else cells.set(k, [p]);
      }
  }
  return (x: number, y: number) => {
    const l = cells.get(key(Math.floor(x / GRID), Math.floor(y / GRID) + 1024));
    let sd = GLOW;
    if (l) for (const p of l) { const dx = p[0] - x, dy = p[1] - y, d = Math.sqrt(dx * dx + dy * dy) - p[2]; if (d < sd) sd = d; } // sqrt, not hypot: much faster
    return sd;
  };
}

let fn: ((x: number, y: number) => number) | undefined;
/** Signed distance (design px) from (x, y) to the nearest channel edge, capped at GLOW. The grid is built once and shared. */
export function nearestChannel(x: number, y: number): number {
  return (fn ??= build())(x, y);
}
