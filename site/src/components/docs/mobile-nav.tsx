"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { usePathname } from "next/navigation";
import { BookOpen, GitPullRequest, LayoutDashboard, Menu, X } from "lucide-react";
import { Sidebar } from "./sidebar";
import { EmfirgeMark } from "./logo";

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** Hamburger + slide-in drawer for < lg, where the sidebar is hidden. */
export function MobileNav() {
  const [open, setOpen] = useState(false);
  const [mounted, setMounted] = useState(false);
  const pathname = usePathname();
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const drawerRef = useRef<HTMLDivElement>(null);

  // Portal target (document.body) is only available after mount.
  useEffect(() => {
    setMounted(true);
  }, []);

  // Close on navigation.
  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  const closeNavigation = useCallback(() => {
    setOpen(false);
    requestAnimationFrame(() => menuButtonRef.current?.focus());
  }, []);

  // Treat the drawer as a modal: lock page scroll, move focus inside, support
  // Escape, and keep keyboard focus within the open navigation.
  useEffect(() => {
    if (!open) return;

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    requestAnimationFrame(() => closeButtonRef.current?.focus());

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        closeNavigation();
        return;
      }

      if (event.key !== "Tab") return;

      const focusable = Array.from(
        drawerRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR) ?? [],
      );
      if (focusable.length === 0) return;

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = previousOverflow;
    };
  }, [closeNavigation, open]);

  // The drawer is rendered through a portal to <body>. If it stayed inside the
  // topbar, the header's `backdrop-filter` would become the containing block
  // for its `position: fixed` layer, trapping/clipping the drawer to the 56px
  // header strip instead of covering the viewport.
  const drawer =
    open &&
    createPortal(
      <div className="fixed inset-0 z-[60] lg:hidden">
        <div
          aria-hidden="true"
          className="absolute inset-0 bg-black/50 backdrop-blur-sm animate-in fade-in duration-200"
          onClick={closeNavigation}
        />
        <div
          ref={drawerRef}
          id="mobile-navigation"
          role="dialog"
          aria-modal="true"
          aria-labelledby="mobile-navigation-title"
          className="rail-scroll absolute left-0 top-0 h-full w-[19rem] max-w-[85vw] overflow-y-auto border-r border-border bg-background p-4 animate-in slide-in-from-left duration-200"
        >
          <div className="mb-5 flex items-center justify-between">
            <span className="flex items-center gap-2">
              <span className="flex size-6 items-center justify-center rounded-md bg-primary text-primary-foreground">
                <EmfirgeMark className="size-4" />
              </span>
              <span
                id="mobile-navigation-title"
                className="font-display text-[18px] font-bold tracking-[-0.03em]"
              >
                emfirge
              </span>
            </span>
            <button
              ref={closeButtonRef}
              type="button"
              aria-label="Close navigation"
              onClick={closeNavigation}
              className="inline-flex size-11 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
            >
              <X className="size-4" />
            </button>
          </div>

          <nav aria-label="Primary" className="mb-6 space-y-1 border-b border-border pb-6">
            <Link
              href="/"
              aria-current="page"
              onClick={closeNavigation}
              className="flex min-h-11 items-center gap-3 rounded-lg bg-accent px-3 text-[13px] font-medium text-foreground"
            >
              <BookOpen className="size-4" />
              Docs
            </Link>
            <a
              href="https://github.com/theanshsonkar/emfirge"
              className="flex min-h-11 items-center gap-3 rounded-lg px-3 text-[13px] text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
            >
              <GitPullRequest className="size-4" />
              GitHub
            </a>
            <a
              href="https://app.emfirge.cloud"
              className="flex min-h-11 items-center gap-3 rounded-lg px-3 text-[13px] text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
            >
              <LayoutDashboard className="size-4" />
              Dashboard
            </a>
          </nav>

          <Sidebar />
        </div>
      </div>,
      document.body,
    );

  return (
    <>
      <button
        ref={menuButtonRef}
        type="button"
        aria-label="Open navigation"
        aria-expanded={open}
        aria-controls="mobile-navigation"
        onClick={() => setOpen(true)}
        className="-ml-1 mr-1 inline-flex size-11 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-accent hover:text-foreground lg:hidden"
      >
        <Menu className="size-4.5" />
      </button>

      {mounted && drawer}
    </>
  );
}
