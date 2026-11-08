"use client";
import { useEffect, useRef, useState } from "react";

/** Live in-view flag (true while on screen) and reduced-motion flag. Figures animate only while `live` and show final state if `still`. */
export function useLive<T extends Element = HTMLDivElement>() {
  const ref = useRef<T>(null);
  const [live, setLive] = useState(false);
  const [still, setStill] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setStill(mq.matches);
    const onMq = () => setStill(mq.matches);
    mq.addEventListener("change", onMq);
    const io = new IntersectionObserver((e) => setLive(e[0].isIntersecting && !document.hidden), { rootMargin: "0px 0px -8% 0px" });
    io.observe(el);
    const onVis = () => { if (document.hidden) setLive(false); };
    document.addEventListener("visibilitychange", onVis);
    return () => { io.disconnect(); mq.removeEventListener("change", onMq); document.removeEventListener("visibilitychange", onVis); };
  }, []);
  return { ref, live, still };
}
