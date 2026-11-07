"use client";

import { useState } from "react";
import { ANNOUNCE } from "@/content";

export function Announcement() {
  const [open, setOpen] = useState(true);
  if (!open) return null;
  return (
    <div className="on-dark relative bg-forest text-mist">
      <div className="mx-auto flex min-h-9 max-w-[1200px] items-center justify-center gap-1.5 px-10 py-1.5 text-center text-[13px] leading-5">
        <p>
          {ANNOUNCE.text}{" "}
          <a href={ANNOUNCE.link.href} className="font-medium text-white underline underline-offset-2">
            {ANNOUNCE.link.label}
          </a>
        </p>
      </div>
      <button
        type="button"
        aria-label={ANNOUNCE.dismiss}
        onClick={() => setOpen(false)}
        className="absolute right-2 top-1/2 flex h-7 w-7 -translate-y-1/2 items-center justify-center rounded text-lg leading-none text-mist-2 hover:text-white"
      >
        <span aria-hidden="true">&times;</span>
      </button>
    </div>
  );
}
