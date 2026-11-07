"use client";

import { useRef, useState } from "react";
import { Check, Copy } from "lucide-react";
import { CONNECT_CMD, HERO } from "@/content";

/** A quiet mono command line with a small copy icon, no box. */
export function CopyCommand() {
  const [done, setDone] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  async function copy() {
    try {
      await navigator.clipboard.writeText(CONNECT_CMD);
      setDone(true);
      clearTimeout(timer.current);
      timer.current = setTimeout(() => setDone(false), 1800);
    } catch {
      /* clipboard unavailable: the command stays selectable */
    }
  }

  return (
    <div className="flex items-center gap-3 font-mono text-[13px] leading-6 text-mist">
      <code>
        <span className="select-none text-mist-2">$ </span>
        {CONNECT_CMD}
      </code>
      <button
        type="button"
        onClick={copy}
        aria-label={HERO.copy}
        className="flex h-7 w-7 items-center justify-center rounded text-mist-2 hover:text-white"
      >
        {done ? <Check size={15} aria-hidden="true" /> : <Copy size={15} aria-hidden="true" />}
      </button>
      <span role="status" className="sr-only">
        {done ? HERO.copied : ""}
      </span>
    </div>
  );
}
