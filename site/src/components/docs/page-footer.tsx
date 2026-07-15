"use client";

import { useState } from "react";
import { usePathname } from "next/navigation";
import { SquarePen, ThumbsUp, ThumbsDown, Check } from "lucide-react";

const REPO = "https://github.com/theanshsonkar/emfirge";

export function PageFooter() {
  const pathname = usePathname();
  const [voted, setVoted] = useState<null | "up" | "down">(null);

  const editHref = `${REPO}/edit/main/emfirge-site/src/app${pathname === "/docs" ? "/docs" : pathname}/page.tsx`;

  return (
    <div className="mt-10 flex flex-col gap-3 border-t border-border pt-5 text-[12.5px] text-muted-foreground sm:flex-row sm:items-center sm:justify-between">
      {voted ? (
        <span className="inline-flex items-center gap-1.5" style={{ color: "var(--safe)" }}>
          <Check className="size-3.5" /> Thanks for the feedback.
        </span>
      ) : (
        <div className="flex items-center gap-2.5">
          <span>Was this page helpful?</span>
          <button
            type="button"
            aria-label="Yes"
            onClick={() => setVoted("up")}
            className="inline-flex size-7 items-center justify-center rounded-md border border-border transition-colors hover:bg-accent hover:text-foreground"
          >
            <ThumbsUp className="size-3.5" />
          </button>
          <button
            type="button"
            aria-label="No"
            onClick={() => setVoted("down")}
            className="inline-flex size-7 items-center justify-center rounded-md border border-border transition-colors hover:bg-accent hover:text-foreground"
          >
            <ThumbsDown className="size-3.5" />
          </button>
        </div>
      )}
      <a
        href={editHref}
        target="_blank"
        rel="noreferrer"
        className="inline-flex items-center gap-1.5 transition-colors hover:text-foreground"
      >
        <SquarePen className="size-3.5" /> Edit this page on GitHub
      </a>
    </div>
  );
}
