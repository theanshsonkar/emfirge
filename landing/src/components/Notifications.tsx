"use client";

import { CalendarClock, LifeBuoy, Rss, Wallet } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { FAMILIAR } from "@/content";
import { cn } from "@/lib/cn";
import { useReduced } from "@/lib/useReduced";
import { H2 } from "./Heading";

const ICON: Record<string, { bg: string; el: React.ReactNode }> = {
  support: { bg: "bg-[#0A84FF]", el: <LifeBuoy size={20} strokeWidth={1.9} /> },
  feed: { bg: "bg-[#FF9F0A]", el: <Rss size={20} strokeWidth={2} /> },
  schedule: { bg: "bg-[#8E5CF0]", el: <CalendarClock size={20} strokeWidth={1.9} /> },
  budget: { bg: "bg-[#30B455]", el: <Wallet size={20} strokeWidth={1.9} /> },
};

// the fan: small x offsets and tilts, only from sm up
const FAN = [
  "sm:translate-x-0 sm:rotate-0",
  "sm:translate-x-5 sm:rotate-[0.7deg]",
  "sm:-translate-x-4 sm:-rotate-[0.6deg]",
  "sm:translate-x-3 sm:rotate-[0.4deg]",
];

export function Notifications() {
  const reduced = useReduced();
  const ref = useRef<HTMLUListElement>(null);
  const [armed, setArmed] = useState(false);
  const [shown, setShown] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (reduced || !el || typeof IntersectionObserver === "undefined") {
      setArmed(false);
      return;
    }
    setArmed(true);
    const io = new IntersectionObserver(
      ([e]) => {
        if (e.isIntersecting) {
          setShown(true);
          io.disconnect();
        }
      },
      { threshold: 0.25 },
    );
    io.observe(el);
    return () => io.disconnect();
  }, [reduced]);

  return (
    <section id="familiar" data-nav="why" className="px-4 pb-[88px] md:pb-[120px]">
      <H2>{FAMILIAR.title}</H2>
      <ul
        ref={ref}
        className={cn(
          "mx-auto mt-10 flex max-w-[388px] flex-col gap-2.5 sm:gap-0",
          armed && "notif-armed",
          shown && "notif-in",
        )}
      >
        {FAMILIAR.items.map((n, i) => (
          <li
            key={n.app}
            className={cn("notif relative sm:-mt-2 sm:first:mt-0", FAN[i])}
            style={{ zIndex: 10 - i, ["--d" as string]: `${i * 110}ms` }}
          >
            <div className="flex gap-2.5 rounded-2xl bg-white/80 p-3 shadow-[0_0_0_0.5px_rgba(0,0,0,0.12),0_10px_28px_-14px_rgba(0,0,0,0.25)] backdrop-blur-xl">
              <span
                className={cn(
                  "flex h-[38px] w-[38px] shrink-0 items-center justify-center rounded-[9px] text-white",
                  ICON[n.icon].bg,
                )}
                aria-hidden="true"
              >
                {ICON[n.icon].el}
              </span>
              <div className="min-w-0 flex-1 text-[13px] leading-[16px]">
                <div className="flex items-baseline justify-between gap-2">
                  <p className="truncate font-semibold text-ink">{n.app}</p>
                  <p className="shrink-0 text-[11px] text-ink-3">now</p>
                </div>
                <p className="mt-0.5 text-ink-2">{n.body}</p>
              </div>
            </div>
          </li>
        ))}
      </ul>
      <p className="mx-auto mt-10 max-w-[520px] text-pretty text-center text-[16px] leading-6 text-ink-2">
        {FAMILIAR.line}
      </p>
    </section>
  );
}
