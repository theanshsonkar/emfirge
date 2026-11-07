import { Check, X } from "lucide-react";
import { WHY } from "@/content";
import { cn } from "@/lib/cn";
import { H2 } from "./Heading";

function Card({ title, items, good }: { title: string; items: string[]; good?: boolean }) {
  return (
    <div className="rounded-2xl bg-surface p-5 shadow-hairline md:p-6">
      <h3 className="text-[15px] font-semibold leading-[22px] tracking-[-0.01em] text-ink">{title}</h3>
      <ul className="mt-4 space-y-3.5">
        {items.map((t) => (
          <li key={t} className="flex items-start gap-2.5 text-[14px] leading-[21px]">
            <span
              className={cn(
                "mt-[3px] flex h-[15px] w-[15px] shrink-0 items-center justify-center rounded-full",
                good ? "bg-pass/12 text-pass" : "bg-black/[0.06] text-ink-3",
              )}
              aria-hidden="true"
            >
              {good ? <Check size={10} strokeWidth={3.2} /> : <X size={10} strokeWidth={3.2} />}
            </span>
            <span className={good ? "text-ink" : "text-ink-2"}>
              <span className="sr-only">{good ? "with: " : "without: "}</span>
              {t}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function Compare() {
  return (
    <section id="why" data-nav="why" className="px-4 pb-[88px] md:pb-[120px]">
      <H2>{WHY.title}</H2>
      <div className="mx-auto mt-10 grid max-w-[780px] gap-3 md:grid-cols-2 md:gap-4">
        <Card title={WHY.without} items={WHY.rows.map((r) => r[0])} />
        <Card title={WHY.with} items={WHY.rows.map((r) => r[1])} good />
      </div>
    </section>
  );
}
