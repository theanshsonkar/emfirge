import { PRICING } from "@/content";

export function Pricing() {
  return (
    <section id="pricing" aria-labelledby="price-h" className="mx-auto max-w-[1320px] px-4 py-16 sm:px-8 lg:py-24">
      <div className="grid gap-10 rounded-[10px] border-2 border-black p-6 sm:p-10 md:grid-cols-2 md:gap-14">
        <div className="flex flex-col items-start">
          <h2 id="price-h" className="display text-[32px] sm:text-[40px]">
            {PRICING.title}
          </h2>
          <p className="mt-4 max-w-[24em]">{PRICING.sub}</p>
          <a
            href={PRICING.cta.href}
            className="label mt-8 rounded-md bg-black px-5 py-3 text-[15px] text-white hover:bg-ink-2"
          >
            {PRICING.cta.label}
          </a>
        </div>
        <ul className="space-y-3 font-mono text-[13.5px]">
          {PRICING.features.map((f) => (
            <li key={f} className="flex gap-3">
              <span aria-hidden="true" className="font-semibold text-pass">
                ✓
              </span>
              {f}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
