"use client";
import { useEffect, useRef } from "react";

export type DrawFn = (ctx: CanvasRenderingContext2D, w: number, h: number, t: number, still: boolean) => void;

/**
 * DPR-aware canvas loop. Pauses while offscreen or in a hidden tab, redraws on resize,
 * and under prefers-reduced-motion draws a single static frame (still = true).
 * `fps` caps the frame rate: the dot fields are cheap but there is no reason to burn 60fps on them.
 */
export function useCanvas(draw: DrawFn, opts: { fps?: number } = {}) {
  const ref = useRef<HTMLCanvasElement>(null);
  const drawRef = useRef(draw);
  drawRef.current = draw;
  const fps = opts.fps ?? 30;

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    let w = 0, h = 0, raf = 0, visible = false, running = false, t0 = 0, last = 0;

    const size = () => {
      const r = canvas.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2.5);
      w = Math.max(1, Math.round(r.width));
      h = Math.max(1, Math.round(r.height));
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    const frame = (now: number) => {
      raf = 0;
      if (!running) return;
      if (now - last >= 1000 / fps - 1) {
        last = now;
        drawRef.current(ctx, w, h, (now - t0) / 1000, false);
      }
      raf = requestAnimationFrame(frame);
    };
    const update = () => {
      const should = visible && !document.hidden && !mq.matches;
      if (should && !running) {
        running = true;
        t0 = performance.now() - (last ? last - t0 : 0);
        raf = requestAnimationFrame(frame);
      } else if (!should && running) {
        running = false;
        if (raf) cancelAnimationFrame(raf);
        raf = 0;
      }
    };
    const still = () => { if (mq.matches) drawRef.current(ctx, w, h, 0, true); };

    size();
    t0 = performance.now();
    drawRef.current(ctx, w, h, 0, mq.matches);
    const io = new IntersectionObserver((e) => { visible = e[0].isIntersecting; update(); }, { rootMargin: "80px" });
    io.observe(canvas);
    const ro = new ResizeObserver(() => { size(); drawRef.current(ctx, w, h, running ? (performance.now() - t0) / 1000 : 0, mq.matches); });
    ro.observe(canvas);
    const onVis = () => update();
    const onMq = () => { update(); still(); };
    document.addEventListener("visibilitychange", onVis);
    mq.addEventListener("change", onMq);
    return () => {
      running = false;
      if (raf) cancelAnimationFrame(raf);
      io.disconnect(); ro.disconnect();
      document.removeEventListener("visibilitychange", onVis);
      mq.removeEventListener("change", onMq);
    };
  }, [fps]);
  return ref;
}
