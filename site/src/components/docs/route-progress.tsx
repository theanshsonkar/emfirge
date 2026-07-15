"use client";

import { useEffect, useRef } from "react";
import { usePathname } from "next/navigation";
import gsap from "gsap";

/** Thin top bar that pulses on client-side route changes for perceived speed. */
export function RouteProgress() {
  const bar = useRef<HTMLDivElement>(null);
  const pathname = usePathname();
  const first = useRef(true);

  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const el = bar.current;
    if (!el) return;
    gsap.killTweensOf(el);
    gsap.set(el, { scaleX: 0, opacity: 1, transformOrigin: "left center" });
    gsap
      .timeline()
      .to(el, { scaleX: 0.8, duration: 0.25, ease: "power2.out" })
      .to(el, { scaleX: 1, duration: 0.15, ease: "power1.out" })
      .to(el, { opacity: 0, duration: 0.2 }, "+=0.02");
  }, [pathname]);

  return (
    <div
      ref={bar}
      aria-hidden
      className="pointer-events-none fixed left-0 top-0 z-[80] h-0.5 w-full bg-foreground opacity-0"
      style={{ transform: "scaleX(0)" }}
    />
  );
}
