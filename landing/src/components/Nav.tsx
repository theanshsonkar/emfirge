"use client";

import { useEffect, useState } from "react";
import { NAV } from "@/content";
import { cn } from "@/lib/cn";

/** Floating centered pill with scroll-spy. Sections opt in with data-nav="<id>". */
export function Nav() {
  const [active, setActive] = useState("top");

  useEffect(() => {
    const els = Array.from(document.querySelectorAll<HTMLElement>("[data-nav]"));
    let raf = 0;
    const update = () => {
      raf = 0;
      let cur = "top";
      for (const el of els) {
        if (el.getBoundingClientRect().top <= 140) cur = el.dataset.nav ?? cur;
      }
      setActive(cur);
    };
    const onScroll = () => {
      if (!raf) raf = requestAnimationFrame(update);
    };
    update();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll);
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
      if (raf) cancelAnimationFrame(raf);
    };
  }, []);

  return (
    <nav aria-label="Primary" className="sticky top-3 z-50 mt-3 flex justify-center px-3">
      <div className="no-scrollbar flex max-w-full items-center gap-0.5 overflow-x-auto rounded-full bg-surface p-1 shadow-hairline">
        {NAV.items.map((it) => (
          <a
            key={it.id}
            href={it.href}
            {...(it.external ? { target: "_blank", rel: "noreferrer" } : {})}
            aria-current={active === it.id ? "true" : undefined}
            className={cn(
              "shrink-0 whitespace-nowrap rounded-full px-3 py-1.5 text-[14px] leading-[21px] tracking-[-0.01em] transition-colors",
              it.strong ? "font-semibold text-ink" : "text-ink-2 hover:text-ink",
              it.external && "text-ink font-medium",
              active === it.id && "bg-black/[0.06] text-ink",
            )}
          >
            {it.label}
          </a>
        ))}
      </div>
    </nav>
  );
}
