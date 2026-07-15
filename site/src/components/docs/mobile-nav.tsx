"use client";

import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { usePathname } from "next/navigation";
import { Menu, X } from "lucide-react";
import { Sidebar } from "./sidebar";
import { EmfirgeMark } from "./logo";

/** Hamburger + slide-in drawer for < lg, where the sidebar is hidden. */
export function MobileNav() {
  const [open, setOpen] = useState(false);
  const [mounted, setMounted] = useState(false);
  const pathname = usePathname();

  // Portal target (document.body) is only available after mount.
  useEffect(() => {
    setMounted(true);
  }, []);

  // Close on navigation.
  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  // Escape to close + lock body scroll while open.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = open ? "hidden" : "";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [open]);

  // The drawer is rendered through a portal to <body>. If it stayed inside the
  // topbar, the header's `backdrop-filter` would become the containing block
  // for its `position: fixed` layer, trapping/clipping the drawer to the 56px
  // header strip instead of covering the viewport.
  const drawer =
    open &&
    createPortal(
      <div className="fixed inset-0 z-[60] lg:hidden">
        <div
          className="absolute inset-0 bg-black/50 backdrop-blur-sm animate-in fade-in duration-200"
          onClick={() => setOpen(false)}
        />
        <div className="rail-scroll absolute left-0 top-0 h-full w-[19rem] max-w-[85vw] overflow-y-auto border-r border-border bg-background p-4 animate-in slide-in-from-left duration-200">
          <div className="mb-5 flex items-center justify-between">
            <span className="flex items-center gap-2">
              <span className="flex size-6 items-center justify-center rounded-md bg-primary text-primary-foreground">
                <EmfirgeMark className="size-4" />
              </span>
              <span className="font-display text-[18px] font-bold tracking-[-0.03em]">emfirge</span>
            </span>
            <button
              type="button"
              aria-label="Close navigation"
              onClick={() => setOpen(false)}
              className="inline-flex size-8 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
            >
              <X className="size-4" />
            </button>
          </div>
          <Sidebar />
        </div>
      </div>,
      document.body,
    );

  return (
    <>
      <button
        type="button"
        aria-label="Open navigation"
        onClick={() => setOpen(true)}
        className="-ml-1 mr-1 inline-flex size-8 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-accent hover:text-foreground lg:hidden"
      >
        <Menu className="size-4.5" />
      </button>

      {mounted && drawer}
    </>
  );
}
