"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ChevronRight } from "lucide-react";
import { NAV } from "@/lib/nav";

/** Docs / <section> / <page> trail, derived from nav + current path. */
export function Breadcrumbs() {
  const pathname = usePathname();

  let section: string | undefined;
  let title: string | undefined;
  let mono = false;
  for (const s of NAV) {
    const item = s.items.find((i) => i.href === pathname);
    if (item) {
      section = s.label;
      title = item.title;
      mono = !!item.mono;
      break;
    }
  }
  if (!title) return null;

  return (
    <nav aria-label="Breadcrumb" className="mb-5 flex flex-wrap items-center gap-1.5 text-[12.5px] text-muted-foreground">
      <Link href="/docs" className="transition-colors hover:text-foreground">Docs</Link>
      {section && (
        <>
          <ChevronRight className="size-3 opacity-60" />
          <span>{section}</span>
        </>
      )}
      <ChevronRight className="size-3 opacity-60" />
      <span className={`text-foreground ${mono ? "font-mono text-[12px]" : ""}`}>{title}</span>
    </nav>
  );
}
