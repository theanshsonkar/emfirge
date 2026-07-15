"use client";

import * as React from "react";
import { usePathname } from "next/navigation";

type Item = { id: string; text: string; level: number };

export function Toc() {
  const pathname = usePathname();
  const [items, setItems] = React.useState<Item[]>([]);
  const [active, setActive] = React.useState<string>("");

  React.useEffect(() => {
    const article = document.querySelector("article");
    if (!article) return;
    const nodes = Array.from(article.querySelectorAll("h2[id], h3[id]")) as HTMLElement[];
    const found = nodes.map((n) => ({
      id: n.id,
      // The heading contains a hover "#" anchor link after the title; read the
      // first anchor (the title link) so the "#" doesn't leak into the TOC.
      text: (n.querySelector("a")?.textContent ?? n.textContent ?? "").trim(),
      level: n.tagName === "H3" ? 3 : 2,
    }));
    setItems(found);

    const visible = new Set<string>();
    const obs = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) visible.add(e.target.id);
          else visible.delete(e.target.id);
        }
        // Activate the top-most heading currently in view (document order),
        // which avoids the highlight jumping when several intersect at once.
        const topMost = found.find((f) => visible.has(f.id));
        if (topMost) setActive(topMost.id);
      },
      { rootMargin: "0px 0px -75% 0px", threshold: 0 },
    );
    nodes.forEach((n) => obs.observe(n));
    return () => obs.disconnect();
  }, [pathname]);

  if (items.length === 0) return null;

  return (
    <div>
      <div className="tag mb-3">On this page</div>
      <ul className="space-y-0.5 border-l border-border-soft text-[12.5px]">
        {items.map((it) => (
          <li key={it.id} className="-ml-px">
            <a
              href={`#${it.id}`}
              className={`relative block rounded-r-md py-1.5 transition-colors ${
                it.level === 3 ? "pl-6" : "pl-4"
              } ${
                active === it.id
                  ? "font-medium text-foreground"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              <span
                className={`absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full transition-colors ${
                  active === it.id ? "bg-foreground" : "bg-transparent"
                }`}
              />
              {it.text}
            </a>
          </li>
        ))}
      </ul>
    </div>
  );
}
