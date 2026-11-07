import { NUMBERS } from "@/content";
import { Frame } from "./Frame";

export function Numbers() {
  return (
    <section aria-label={NUMBERS.label} className="border-b border-line bg-white">
      <Frame>
        <dl className="grid gap-10 px-4 py-14 text-center sm:px-8 md:grid-cols-3 lg:px-12 lg:py-20">
          {NUMBERS.items.map((n) => (
            <div key={n.figure} className="flex flex-col-reverse items-center gap-2">
              <dt className="max-w-[24ch] text-base text-ink-2">{n.label}</dt>
              <dd className="text-[56px] font-medium leading-none tracking-[-0.035em] text-ink sm:text-[64px]">{n.figure}</dd>
            </div>
          ))}
        </dl>
      </Frame>
    </section>
  );
}
