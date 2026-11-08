"use client";

import { LIVE_BAR } from "@/content";
import { useLab } from "./LabProvider";

/** The promise, always visible: whatever you do below, live doesn't move. */
export function LiveBar() {
  const { state, caught } = useLab();
  return (
    <div className="sticky top-0 z-50 flex h-10 items-center justify-between gap-3 bg-black px-4 font-mono text-[12px] text-white sm:px-8 sm:text-[13px]">
      <p className="flex min-w-0 items-center gap-2 whitespace-nowrap">
        <span aria-hidden="true" className="live-dot inline-block size-2 rounded-full bg-pass" />
        <span>live</span>
        <span className="hidden text-white/50 sm:inline">·</span>
        <span className="hidden sm:inline">{LIVE_BAR.resources} resources</span>
        <span className="text-white/50">·</span>
        <span>
          0 changes<span className="hidden md:inline"> since you arrived</span>
        </span>
      </p>
      <p className="flex items-center gap-3 whitespace-nowrap sm:gap-5">
        <span>
          caught {caught}
          <span className="hidden min-[420px]:inline"> of </span>
          <span className="min-[420px]:hidden">/</span>
          {state.tests.length}
        </span>
        <a href={LIVE_BAR.cta.href} className="underline underline-offset-4 hover:text-crash">
          {LIVE_BAR.cta.label}
        </a>
      </p>
    </div>
  );
}
