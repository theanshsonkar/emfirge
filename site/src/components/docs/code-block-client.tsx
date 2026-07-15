"use client";

import * as React from "react";
import { Check, Copy } from "lucide-react";

type RenderedTab = { label: string; code: string; html: string };

export function CodeBlockClient({
  tabs,
  numbered = false,
  footer,
  className = "",
}: {
  tabs: RenderedTab[];
  numbered?: boolean;
  footer?: React.ReactNode;
  className?: string;
}) {
  const [active, setActive] = React.useState(0);
  const [copied, setCopied] = React.useState(false);
  const tab = tabs[active];

  return (
    <div
      className={`code-rail my-6 overflow-hidden rounded-xl border shadow-[0_1px_2px_oklch(0_0_0/0.04),0_16px_40px_-24px_oklch(0_0_0/0.35)] ${className}`}
      style={{ background: "var(--code-bg)", borderColor: "var(--code-border)" }}
    >
      <div className="flex items-center gap-1 border-b px-2.5 py-2" style={{ borderColor: "var(--code-border)" }}>
        {tabs.length > 1 ? (
          tabs.map((t, i) => (
            <button
              key={t.label}
              onClick={() => setActive(i)}
              className="rounded-md px-2.5 py-1 font-mono text-[12px] transition-colors hover:text-white"
              style={i === active ? { background: "var(--code-bg-2)", color: "var(--code-fg)" } : { color: "var(--code-muted)" }}
            >
              {t.label}
            </button>
          ))
        ) : (
          <span className="flex items-center gap-2 px-2 py-1 font-mono text-[11px] uppercase tracking-[0.14em]" style={{ color: "var(--code-muted)" }}>
            <span className="inline-block size-1.5 rounded-full" style={{ background: "var(--code-muted)" }} aria-hidden />
            {tab.label}
          </span>
        )}
        <button
          onClick={() => {
            navigator.clipboard?.writeText(tab.code).catch(() => {});
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          }}
          className="ml-auto flex size-6 items-center justify-center rounded-md transition-colors hover:bg-white/10"
          style={{ color: "var(--code-muted)" }}
          aria-label="Copy code"
        >
          {copied ? <Check className="size-3.5" style={{ color: "var(--safe)" }} /> : <Copy className="size-3.5" />}
        </button>
      </div>
      <div
        className={`shiki-scroll overflow-x-auto px-4 py-3.5 text-[12.5px] leading-[1.75] ${numbered ? "shiki-numbered" : ""}`}
        dangerouslySetInnerHTML={{ __html: tab.html }}
      />
      {footer && (
        <div className="flex items-center gap-2 border-t px-4 py-2.5 text-[12px]" style={{ borderColor: "var(--code-border)", color: "var(--code-muted)" }}>
          {footer}
        </div>
      )}
    </div>
  );
}
