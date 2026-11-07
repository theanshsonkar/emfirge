import { Plus } from "lucide-react";
import { FAQ } from "@/content";
import { H2 } from "./Heading";

export function Faq() {
  return (
    <section id="faq" data-nav="faq" className="px-4 pb-[88px] md:pb-[120px]">
      <H2>{FAQ.title}</H2>
      <div className="mx-auto mt-10 max-w-[720px] space-y-2">
        {FAQ.items.map((f) => (
          <details key={f.q} className="group rounded-xl bg-surface shadow-hairline">
            <summary className="flex cursor-pointer list-none items-center justify-between gap-4 px-5 py-4 text-[16px] font-medium leading-6 tracking-[-0.01em] text-ink">
              {f.q}
              <Plus
                size={16}
                strokeWidth={2}
                className="shrink-0 text-ink-3 transition-transform group-open:rotate-45"
                aria-hidden="true"
              />
            </summary>
            <p className="px-5 pb-5 text-[15px] leading-[23px] text-ink-2">{f.a}</p>
          </details>
        ))}
      </div>
    </section>
  );
}
