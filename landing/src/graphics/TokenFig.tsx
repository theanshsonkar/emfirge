"use client";
import { useEffect, useRef, useState } from "react";
import { useLive } from "./useLive";

// Security figure 2: an account ID scrambles into a token once, in view, on your machine, before the model. Final text without motion.
const REAL = "123456789012", TOKEN = "acct_7f3a…", POOL = "0123456789abcdef";

export function TokenFig() {
  const { ref, live, still } = useLive<HTMLDivElement>();
  const [txt, setTxt] = useState(TOKEN);
  const done = useRef(false);
  useEffect(() => {
    if (!live || still || done.current) return;
    done.current = true;
    const t0 = performance.now();
    let raf = 0;
    const step = (now: number) => {
      const k = Math.min(1, (now - t0) / 1100);
      const lock = Math.floor(k * TOKEN.length);
      setTxt([...TOKEN].map((c, i) => (i < lock || c === "_" || c === "…" ? c : POOL[Math.floor(Math.random() * 16)])).join(""));
      if (k < 1) raf = requestAnimationFrame(step); else setTxt(TOKEN);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [live, still]);
  return (
    <div ref={ref} className="tok">
      <div className="tk-b"><span className="label">Your machine</span><code>{REAL}</code><small>account ID</small></div>
      <div className="tk-m" aria-hidden="true"><svg width="48" height="12" viewBox="0 0 48 12" fill="none" stroke="currentColor" strokeWidth="1.1"><path d="M0 6H46M41 1.5L46 6L41 10.5" /></svg><span className="label">tokenize</span></div>
      <div className="tk-b g"><span className="label">The model sees</span><code aria-live="off">{txt}</code><small>token</small></div>
      <p className="tk-f">The token map, <span>~/.emfirge/tokens.json</span>, stays on your machine.</p>
    </div>
  );
}
export default TokenFig;
