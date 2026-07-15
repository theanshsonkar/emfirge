"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Command } from "cmdk";
import { Search, CornerDownLeft } from "lucide-react";
import { NAV } from "@/lib/nav";
import { SEARCH_ITEMS } from "@/lib/search";

export function CommandMenu() {
  const [open, setOpen] = useState(false);
  const router = useRouter();

  // ⌘K / Ctrl+K to toggle.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  const sections = useMemo(() => NAV.map((s) => s.label), []);

  const go = (href: string) => {
    setOpen(false);
    router.push(href);
  };

  return (
    <>
      {/* Desktop trigger (matches the topbar control styling) */}
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="hidden items-center gap-2 rounded-lg border border-border px-3 py-1.5 text-[13px] text-muted-foreground transition-colors hover:bg-accent hover:text-foreground sm:flex"
      >
        <Search className="size-3.5" />
        <span>Search</span>
        <kbd className="ml-4 rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[10px]">⌘K</kbd>
      </button>

      {/* Mobile trigger (icon only) */}
      <button
        type="button"
        aria-label="Search docs"
        onClick={() => setOpen(true)}
        className="inline-flex size-8 items-center justify-center rounded-lg border border-border text-muted-foreground transition-colors hover:bg-accent hover:text-foreground sm:hidden"
      >
        <Search className="size-4" />
      </button>

      <Command.Dialog
        open={open}
        onOpenChange={setOpen}
        label="Search documentation"
        shouldFilter
        loop
      >
        <Command.Input placeholder="Search the docs…" />
        <Command.List>
          <Command.Empty>No results found.</Command.Empty>
          {sections.map((section) => {
            const items = SEARCH_ITEMS.filter((i) => i.section === section);
            if (!items.length) return null;
            return (
              <Command.Group key={section} heading={section}>
                {items.map((i) => (
                  <Command.Item
                    key={i.href}
                    value={`${i.title} ${i.section} ${i.keywords}`}
                    onSelect={() => go(i.href)}
                  >
                    <span className={i.mono ? "font-mono text-[13px]" : "text-[13.5px]"}>{i.title}</span>
                    <CornerDownLeft className="cmdk-enter size-3.5" />
                  </Command.Item>
                ))}
              </Command.Group>
            );
          })}
        </Command.List>
      </Command.Dialog>
    </>
  );
}
