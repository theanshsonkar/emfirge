"use client";

import { useState } from "react";
import { COMMAND } from "@/content";

export function CopyCommand() {
  const [done, setDone] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(COMMAND);
      setDone(true);
      setTimeout(() => setDone(false), 1600);
    } catch {
      /* clipboard blocked: the command is selectable text */
    }
  }
  return (
    <div className="flex max-w-full items-stretch overflow-hidden rounded-md border-2 border-black bg-white font-mono text-[14px]">
      <code className="min-w-0 flex-1 select-all overflow-x-auto whitespace-nowrap px-3 py-2">{COMMAND}</code>
      <button
        type="button"
        onClick={copy}
        className="label border-l-2 border-black bg-black px-3 text-white hover:bg-ink-2"
        aria-live="polite"
      >
        {done ? "copied" : "copy"}
      </button>
    </div>
  );
}
