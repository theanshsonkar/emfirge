"use client";
import { useState } from "react";
import { Check, Copy } from "./Icons";

export function CopyMd({ mdUrl }: { mdUrl: string }) {
  const [s, setS] = useState<"idle" | "done" | "err">("idle");
  const copy = async () => {
    try {
      const r = await fetch(mdUrl);
      if (!r.ok) throw new Error(String(r.status));
      const t = await r.text();
      try { await navigator.clipboard.writeText(t); } catch {
        const a = document.createElement("textarea"); a.value = t; document.body.appendChild(a); a.select();
        document.execCommand("copy"); a.remove();
      }
      setS("done");
    } catch { setS("err"); }
    setTimeout(() => setS("idle"), 1800);
  };
  return (
    <div className="dp-tools">
      <button className="cpm" onClick={copy} aria-live="polite">
        <span aria-hidden="true">{s === "done" ? <Check /> : <Copy />}</span>
        {s === "done" ? "Copied" : s === "err" ? "Could not copy" : "Copy page as markdown"}
      </button>
      <a className="cpm lnk" href={mdUrl}>View .md</a>
    </div>
  );
}
