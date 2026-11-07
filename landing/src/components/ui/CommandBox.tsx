"use client";

import { useEffect, useRef, useState } from "react";
import { Check, Copy } from "lucide-react";
import { cn } from "@/lib/cn";

export function CommandBox({ command, className }: { command: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);

  async function copy() {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1800);
    } catch {
      /* clipboard unavailable: the command text stays selectable */
    }
  }

  return (
    <div
      className={cn(
        "flex h-12 w-full max-w-full items-center gap-3 rounded-xl border border-line bg-surface pl-4 pr-1.5 font-mono text-[13px] sm:text-sm",
        className,
      )}
    >
      <span className="select-none text-muted" aria-hidden="true">$</span>
      <code className="min-w-0 flex-1 select-all truncate text-paper">{command}</code>
      <button
        type="button"
        onClick={copy}
        aria-label={copied ? "Copied" : `Copy command: ${command}`}
        className="inline-flex h-9 shrink-0 items-center gap-1.5 rounded-lg px-3 font-sans text-[13px] font-medium text-paper hover:bg-line"
      >
        {copied ? <Check size={15} className="text-pass" /> : <Copy size={15} />}
        <span aria-live="polite">{copied ? "Copied" : "Copy"}</span>
      </button>
    </div>
  );
}
