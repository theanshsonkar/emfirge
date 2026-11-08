"use client";
import { useState } from "react";

export function CodeBlock({ title, text }: { title?: string; text: string }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(text); } catch {
      const t = document.createElement("textarea"); t.value = text; document.body.appendChild(t); t.select();
      try { document.execCommand("copy"); } catch {} t.remove();
    }
    setDone(true); setTimeout(() => setDone(false), 1600);
  };
  return (
    <div className="codeb">
      <div className="codeb-h"><span className="label">{title ?? "Code"}</span><button onClick={copy} aria-live="polite">{done ? "Copied" : "Copy"}</button></div>
      <pre><code>{text}</code></pre>
    </div>
  );
}
