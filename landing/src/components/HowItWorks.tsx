"use client";

import { useState } from "react";
import { HOW, TABS } from "@/content";
import { cn } from "@/lib/cn";
import { H2 } from "./Heading";
import { MacWindow } from "./MacWindow";
import { TerminalScript } from "./TerminalScript";

export function HowItWorks() {
  const [tab, setTab] = useState(TABS[0].id);
  return (
    <section id="how" data-nav="how" className="px-4 py-[88px] md:py-[120px]">
      <H2>{HOW.title}</H2>
      <p className="mx-auto mt-3 max-w-[520px] text-center text-[16px] leading-6 text-ink-2">{HOW.sub}</p>

      <div className="no-scrollbar -mx-4 mt-8 overflow-x-auto px-4">
        <div role="tablist" aria-label="kinds of cloud work" className="mx-auto flex w-max gap-1.5">
          {TABS.map((t) => (
            <button
              key={t.id}
              role="tab"
              id={`tab-${t.id}`}
              aria-selected={tab === t.id}
              aria-controls={`panel-${t.id}`}
              onClick={() => setTab(t.id)}
              className={cn(
                "rounded-full px-4 py-1.5 text-[14px] leading-[21px] tracking-[-0.01em] shadow-hairline transition-colors",
                tab === t.id ? "bg-ink text-white shadow-none" : "bg-surface text-ink-2 hover:text-ink",
              )}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* All transcripts share one grid cell, so the window keeps the height of the tallest. */}
      <div className="mx-auto mt-8 grid w-full max-w-[780px]">
        <MacWindow variant="terminal" title="~/infra — zsh" className="col-start-1 row-start-1">
          <div className="grid">
            {TABS.map((t) => (
              <div
                key={t.id}
                role="tabpanel"
                id={`panel-${t.id}`}
                aria-labelledby={`tab-${t.id}`}
                aria-hidden={tab !== t.id}
                inert={tab !== t.id}
                className={cn(
                  "col-start-1 row-start-1 transition-opacity duration-150",
                  tab === t.id ? "opacity-100" : "pointer-events-none opacity-0",
                )}
              >
                <TerminalScript lines={t.lines} className="min-h-[240px] sm:min-h-[220px]" />
              </div>
            ))}
          </div>
        </MacWindow>
      </div>
    </section>
  );
}
