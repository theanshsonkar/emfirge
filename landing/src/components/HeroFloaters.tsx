"use client";

import { X } from "lucide-react";
import { useState } from "react";
import { HERO } from "@/content";

/** Left floating toast (desktop only). A placeholder, clearly marked. */
export function HeroToast() {
  const [open, setOpen] = useState(true);
  if (!open) return null;
  return (
    <aside
      aria-label="placeholder testimonial"
      className="absolute bottom-10 left-6 z-20 hidden w-[272px] rounded-2xl bg-surface p-4 text-left shadow-[0_0_0_0.5px_rgba(0,0,0,0.12),0_12px_32px_-16px_rgba(0,0,0,0.18)] min-[1320px]:block"
    >
      <div className="pointer-events-none absolute inset-1 rounded-[12px] border border-dashed border-black/15" aria-hidden="true" />
      <button
        type="button"
        onClick={() => setOpen(false)}
        aria-label="dismiss"
        className="absolute right-3 top-3 text-ink-3 hover:text-ink"
      >
        <X size={13} />
      </button>
      <span className="inline-flex rounded-md bg-black/[0.06] px-1.5 py-0.5 text-[11px] font-medium leading-[14px] text-ink-2">
        {HERO.toast.chip}
      </span>
      <p className="mt-2 pr-3 text-[14px] leading-[21px] text-ink">{HERO.toast.text}</p>
      <p className="mt-3 text-[13px] leading-[18px] text-ink-3">{HERO.toast.handle}</p>
    </aside>
  );
}

/** Right hand note with a hand-drawn arrow curving down to the window (desktop only). */
export function HandNote() {
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none absolute left-full top-1 ml-6 hidden w-[200px] min-[1320px]:block"
    >
      <p className="-rotate-3 font-hand text-[24px] leading-[26px] text-ink-2">{HERO.hand}</p>
      <svg width="96" height="84" viewBox="0 0 96 84" fill="none" className="mt-1 text-ink-2">
        <path
          d="M82 6C74 38 48 62 12 70"
          stroke="currentColor"
          strokeWidth="1.6"
          strokeLinecap="round"
        />
        <path d="M24 60L10 70.5L26 78" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </div>
  );
}
