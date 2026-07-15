"use client";

import { useEffect } from "react";
import { usePathname } from "next/navigation";

/**
 * Resets scroll to the top on client-side route changes.
 *
 * Next's App Router scroll-to-top can be defeated by the global
 * `html { scroll-behavior: smooth }` rule (the smooth animation races the
 * segment swap, so the new page opens at the previous scroll position).
 * We keep smooth scrolling for in-page TOC anchors and force an instant
 * jump to the top only on pathname changes.
 *
 * Guards:
 * - If the URL carries a hash (deep link / command-menu jump to a section),
 *   we leave scrolling to the browser so the anchor still wins.
 */
export function ScrollToTop() {
  const pathname = usePathname();

  useEffect(() => {
    if (typeof window === "undefined") return;
    if (window.location.hash) return;
    // `instant` so it doesn't inherit the page's smooth scroll-behavior.
    window.scrollTo({ top: 0, left: 0, behavior: "instant" as ScrollBehavior });
  }, [pathname]);

  return null;
}
