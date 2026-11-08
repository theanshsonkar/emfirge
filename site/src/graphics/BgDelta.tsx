"use client";
import { useEffect, useRef } from "react";
import { BAYER4, fbm } from "./noise";
import { DH, DW, SEGS } from "./deltaGeom";

// Full-width, static river-delta backdrop for desktop (>= 1024px). One fixed canvas behind the rail and the page.
// Same geometry and dither as the hero delta (Delta.tsx), scaled to the viewport width and centred vertically.
// A CSS mask fades it out behind the reading column, so it only shows in the margins.
const CELL = 5;          // device-independent px per dither cell
const GLOW = 11;         // design px: how far a channel lights its banks (beyond this the distance no longer matters)
const GRID = 16;         // design px: spatial-grid cell, >= max channel radius + GLOW so a 1-cell lookup is exact
const LEVELS = 10;       // land-dot alpha buckets (batched fills instead of one fillStyle per dot)
const G = "10,122,75";
const DESKTOP = "(min-width: 1024px)";

type Pt = [number, number, number];

// Channel points bucketed into a coarse grid: each point is stored in every cell its influence box touches,
// so the nearest-channel lookup for a cell only has to scan that one cell's list.
function buildGrid() {
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
    let sd = GLOW; // capped: past GLOW only "not water, no bank glow" matters
    if (l) for (const p of l) { const dx = p[0] - x, dy = p[1] - y, d = Math.sqrt(dx * dx + dy * dy) - p[2]; if (d < sd) sd = d; } // sqrt, not hypot: much faster
    return sd;
  };
}

function paint(cv: HTMLCanvasElement, w: number, h: number) {
  const t0 = performance.now();
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
  const ctx = cv.getContext("2d");
  if (!ctx) return;
  ctx.scale(dpr, dpr);
  const sc = w / DW;
  const yOff = (DH * sc - h) / 2 / sc; // centre the delta vertically
  const cols = Math.ceil(w / CELL), rows = Math.ceil(h / CELL);
  const nearest = buildGrid();
  const water: number[] = [];
  const land: number[][] = Array.from({ length: LEVELS }, () => []);
  for (let j = 0; j < rows; j++) for (let i = 0; i < cols; i++) {
    const sd = nearest(((i + 0.5) * CELL) / sc, ((j + 0.5) * CELL) / sc + yOff);
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
  try { performance.measure("bgdelta-draw", { start: t0, end: performance.now() }); } catch { /* User Timing unavailable */ }
}

// Mask: faint behind the rail, a touch stronger at the rail edge, gone behind the column, back to full beyond it.
function mask(cv: HTMLCanvasElement, w: number) {
  const col = document.querySelector(".col")?.getBoundingClientRect();
  const rail = document.querySelector(".rail")?.getBoundingClientRect();
  if (!col || !rail) return;
  const p = (v: number) => `${((v / w) * 100).toFixed(1)}%`;
  const m = `linear-gradient(to right,rgba(0,0,0,.28) 0,rgba(0,0,0,.28) ${p(rail.right - 40)},rgba(0,0,0,.5) ${p(rail.right)},rgba(0,0,0,0) ${p(col.left + 40)},rgba(0,0,0,0) ${p(col.right - 20)},#000 ${p(Math.min(w, col.right + 180))})`;
  cv.style.webkitMaskImage = m;
  cv.style.maskImage = m;
}

export function BgDelta() {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const cv = ref.current;
    if (!cv) return;
    const mq = window.matchMedia(DESKTOP);
    let drawn = "", idle = 0, debounce = 0;
    const cancelIdle = () => {
      if (!idle) return;
      if (typeof cancelIdleCallback === "function") cancelIdleCallback(idle); else clearTimeout(idle);
      idle = 0;
    };
    const update = () => {
      if (!mq.matches) { cancelIdle(); drawn = ""; cv.width = cv.height = 0; return; } // phones/tablets: compute nothing
      const w = document.documentElement.clientWidth, h = document.documentElement.clientHeight;
      mask(cv, w);
      const key = `${w}x${h}@${window.devicePixelRatio}`;
      if (key === drawn) return;
      cancelIdle();
      const run = () => { idle = 0; drawn = key; paint(cv, w, h); };
      idle = typeof requestIdleCallback === "function" ? requestIdleCallback(run, { timeout: 500 }) : window.setTimeout(run, 0);
    };
    const onResize = () => { clearTimeout(debounce); debounce = window.setTimeout(update, 150); };
    update();
    window.addEventListener("resize", onResize);
    mq.addEventListener("change", update);
    return () => {
      clearTimeout(debounce); cancelIdle();
      window.removeEventListener("resize", onResize);
      mq.removeEventListener("change", update);
    };
  }, []);
  return <canvas ref={ref} className="bgdelta" aria-hidden="true" />;
}
