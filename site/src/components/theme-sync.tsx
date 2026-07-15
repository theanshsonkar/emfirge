"use client";

import { useEffect } from "react";
import { useTheme } from "next-themes";

// Dev aid: allow ?theme=light|dark to force a theme (used for screenshots).
// Gated to development so a stray ?theme= link can't silently persist a
// theme override into a real visitor's localStorage in production.
export function ThemeSync() {
  const { setTheme } = useTheme();
  useEffect(() => {
    if (process.env.NODE_ENV === "production") return;
    const t = new URLSearchParams(window.location.search).get("theme");
    if (t === "light" || t === "dark") setTheme(t);
  }, [setTheme]);
  return null;
}
