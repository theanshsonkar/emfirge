"use client";

import * as React from "react";
import { usePathname } from "next/navigation";
import { ChevronDown } from "lucide-react";

type Item = { id: string; text: string; level: number };

/**
 * Collapsible "On this page" for < xl screens, where the right-hand TOC rail
 * is hidden. Extracts the same h2/h3 anchors the desktop TOC uses.
 */
export function MobileToc() {
  const pathname = usePathname();
  const [items, setItems] = React.useState<Item[]>([]);
  const detailsRef = React.useRef<HTMLDetailsElement>(null);

  React.useEffect(() => {
    const article = document.querySelector("article");
    if (!article) return;
    const nodes = Array.from(article.querySelectorAll("h2[id], h3[id]")) as HTMLElement[];
    setItems(
      nodes.map((n) => ({
        id: n.id,
        text: (n.querySelector("a")?.textContent ?? n.textContent ?? "").trim(),
        level: n.tagName === "H3" ? 3 : 2,
      })),
    );
  }, [pathname]);

  if (items.length === 0) return null;

  return (
    <details ref={detailsRef} className="group mb-8 rounded-md border border-border bg-surface xl:hidden">
      <summary className="flex cursor-pointer list-none items-center justify-between px-4 py-2.5 [&::-webkit-details-marker]:hidden">
        <span className="tag">On this page</span>
        <ChevronDown className="size-4 text-muted-foreground transition-transform duration-200 group-open:rotate-180" />
      </summary>
      <ul className="border-t border-border-soft px-2 py-2 text-[13.5px]">
        {items.map((it) => (
          <li key={it.id}>
            <a
              href={`#${it.id}`}
              onClick={() => detailsRef.current?.removeAttribute("open")}
              className={`block rounded py-1.5 text-muted-foreground transition-colors hover:text-foreground ${
                it.level === 3 ? "pl-7" : "pl-3"
              }`}
            >
              {it.text}
            </a>
          </li>
        ))}
      </ul>
    </details>
  );
}
