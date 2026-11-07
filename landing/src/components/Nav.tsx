"use client";

import { useEffect, useRef, useState } from "react";
import { NAV } from "@/content";
import { Button } from "./Button";
import { Logo } from "./Logo";
import { Frame } from "./Frame";

export function Nav() {
  const [open, setOpen] = useState(false);
  const btn = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        btn.current?.focus();
      }
    };
    const mq = window.matchMedia("(min-width: 768px)");
    const onMq = () => mq.matches && setOpen(false);
    document.addEventListener("keydown", onKey);
    mq.addEventListener("change", onMq);
    return () => {
      document.removeEventListener("keydown", onKey);
      mq.removeEventListener("change", onMq);
    };
  }, [open]);

  const menuItems = [...NAV.items, { label: NAV.signIn.label, href: NAV.signIn.href }];

  return (
    <header className="sticky top-0 z-40 border-b border-line bg-white">
      <Frame>
        <nav aria-label="Primary" className="flex h-16 items-center justify-between gap-4 px-4 sm:px-6">
          <div className="flex items-center gap-8">
            <a href="#top" aria-label={NAV.home} className="text-ink">
              <Logo />
            </a>
            <ul className="hidden items-center gap-6 md:flex">
              {NAV.items.map((i) => (
                <li key={i.label}>
                  <a href={i.href} className="text-sm font-medium text-ink-2 hover:text-ink">
                    {i.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>
          <div className="flex items-center gap-2">
            <Button href={NAV.signIn.href} variant="outline" className="max-md:hidden">
              {NAV.signIn.label}
            </Button>
            <Button href={NAV.start.href}>{NAV.start.label}</Button>
            <button
              ref={btn}
              type="button"
              aria-expanded={open}
              aria-controls="mobile-menu"
              onClick={() => setOpen((o) => !o)}
              className="inline-flex items-center gap-2 rounded-[4px] border border-ink bg-white px-3 py-2 text-sm font-medium leading-5 text-ink hover:bg-paper md:hidden"
            >
              <span aria-hidden="true" className="flex flex-col gap-[3px]">
                <span className="block h-[1.5px] w-3.5 bg-ink" />
                <span className="block h-[1.5px] w-3.5 bg-ink" />
              </span>
              {open ? NAV.menu.close : NAV.menu.open}
            </button>
          </div>
        </nav>
        {open && (
          <div id="mobile-menu" className="border-t border-line bg-white md:hidden">
            <ul aria-label={NAV.menu.label} className="divide-y divide-line">
              {menuItems.map((i) => (
                <li key={i.label}>
                  <a
                    href={i.href}
                    onClick={() => setOpen(false)}
                    className="block px-4 py-4 text-base font-medium text-ink hover:bg-paper focus-visible:bg-paper focus-visible:outline-offset-[-2px] sm:px-6"
                  >
                    {i.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Frame>
    </header>
  );
}
