"use client";
import { useEffect, useRef } from "react";
import { MAX_DPR, paintBackdrop, type MaskStops } from "./bgdeltaPaint";
import type { BgJob, BgResult } from "./bgdelta.worker";

// Full-width, static river-delta backdrop for desktop (>= 1024px). One fixed element behind the rail and the page.
// Same geometry and dither as the hero delta (Delta.tsx), scaled to the viewport width and centred vertically.
// The reading column is faded out so the delta only shows in the margins. The fade is baked into the bitmap's alpha
// (not a CSS mask, and not a live <canvas>): both made the compositor re-commit the layer on every frame and made
// scrolling janky. The bitmap is drawn offscreen (worker when possible), turned into a blob URL and shown as a
// background-image on a plain fixed div.
const DESKTOP = "(min-width: 1024px)";

// Mask: faint behind the rail, a touch stronger at the rail edge, gone behind the column, back to full beyond it.
// Positions are fractions of the viewport width, rounded to 0.1% and kept ascending within 0..1 (as CSS would clamp them).
function maskStops(w: number): MaskStops | null {
  const col = document.querySelector(".col")?.getBoundingClientRect();
  const rail = document.querySelector(".rail")?.getBoundingClientRect();
  if (!col || !rail) return null;
  let prev = 0;
  const p = (v: number) => (prev = Math.max(prev, Math.min(1, Math.max(0, Math.round((v / w) * 1000) / 1000))));
  return [
    [p(0), 0.28], [p(rail.right - 40), 0.28], [p(rail.right), 0.5],
    [p(col.left + 40), 0], [p(col.right - 20), 0], [p(Math.min(w, col.right + 180)), 1],
  ];
}

// Main-thread fallback: a detached canvas, drawn in an idle callback.
function renderHere(job: BgJob): Promise<Blob> {
  const cv = document.createElement("canvas");
  cv.width = Math.round(job.w * job.dpr); cv.height = Math.round(job.h * job.dpr);
  const ctx = cv.getContext("2d");
  if (!ctx) return Promise.reject(new Error("no 2d context"));
  paintBackdrop(ctx, job.w, job.h, job.dpr, job.stops);
  return new Promise((res, rej) => cv.toBlob((b) => (b ? res(b) : rej(new Error("toBlob failed"))), "image/png"));
}

export function BgDelta() {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const mq = window.matchMedia(DESKTOP);
    let cur: BgJob | null = null, drawn = "", idle = 0, debounce = 0, gen = 0, url = "", worker: Worker | null = null, workerOk = typeof Worker !== "undefined" && typeof OffscreenCanvas !== "undefined";
    const cancelIdle = () => {
      if (!idle) return;
      if (typeof cancelIdleCallback === "function") cancelIdleCallback(idle); else clearTimeout(idle);
      idle = 0;
    };
    const show = (blob: Blob | null) => {
      const old = url;
      url = blob ? URL.createObjectURL(blob) : "";
      el.style.backgroundImage = url ? `url("${url}")` : "";
      if (old) URL.revokeObjectURL(old);
    };
    const fallback = (job: BgJob) => {
      idle = typeof requestIdleCallback === "function"
        ? requestIdleCallback(() => { idle = 0; renderHere(job).then((b) => { if (job.id === gen) show(b); }, () => { /* keep the previous bitmap */ }); }, { timeout: 500 })
        : window.setTimeout(() => { idle = 0; renderHere(job).then((b) => { if (job.id === gen) show(b); }, () => {}); }, 0);
    };
    const render = (job: BgJob) => {
      cur = job;
      if (workerOk) {
        try {
          if (!worker) {
            worker = new Worker(new URL("./bgdelta.worker.ts", import.meta.url));
            worker.onmessage = ({ data }: MessageEvent<BgResult>) => {
              if (data.id !== gen) return; // superseded by a newer draw
              if (data.blob) show(data.blob);
              else { workerOk = false; if (cur) fallback(cur); } // worker could not draw (e.g. no OffscreenCanvas 2d): do it here
            };
            worker.onerror = () => { workerOk = false; worker?.terminate(); worker = null; if (cur && cur.id === gen) fallback(cur); };
          }
          worker.postMessage(job);
          return;
        } catch { workerOk = false; worker = null; }
      }
      fallback(job);
    };
    const update = () => {
      if (!mq.matches) { cancelIdle(); gen++; drawn = ""; show(null); return; } // phones/tablets: compute nothing
      const w = document.documentElement.clientWidth, h = document.documentElement.clientHeight;
      const dpr = Math.min(window.devicePixelRatio || 1, MAX_DPR);
      const stops = maskStops(w);
      const key = `${w}x${h}@${dpr}:${JSON.stringify(stops)}`;
      if (key === drawn) return;
      drawn = key;
      cancelIdle();
      render({ id: ++gen, w, h, dpr, stops });
    };
    const onResize = () => { clearTimeout(debounce); debounce = window.setTimeout(update, 150); };
    update();
    window.addEventListener("resize", onResize);
    mq.addEventListener("change", update);
    return () => {
      gen++; clearTimeout(debounce); cancelIdle();
      window.removeEventListener("resize", onResize);
      mq.removeEventListener("change", update);
      worker?.terminate(); worker = null;
      if (url) { URL.revokeObjectURL(url); url = ""; }
    };
  }, []);
  return <div ref={ref} className="bgdelta" aria-hidden="true" />;
}
