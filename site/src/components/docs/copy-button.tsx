"use client";

import * as React from "react";
import { Check, Copy } from "lucide-react";

/** Small copy-to-clipboard button with a brief "Copied" confirmation. */
export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = React.useState(false);
  return (
    <span className="relative flex shrink-0 items-center">
      {copied && (
        <span className="pointer-events-none absolute right-full mr-2 rounded bg-foreground px-1.5 py-0.5 text-[10.5px] font-medium text-background">
          Copied
        </span>
      )}
      <button
        type="button"
        aria-label={label}
        onClick={() => {
          navigator.clipboard?.writeText(text).catch(() => {});
          setCopied(true);
          setTimeout(() => setCopied(false), 1400);
        }}
        className="flex size-7 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
      >
        {copied ? (
          <Check className="size-3.5" style={{ color: "var(--safe)" }} />
        ) : (
          <Copy className="size-3.5" />
        )}
      </button>
    </span>
  );
}
