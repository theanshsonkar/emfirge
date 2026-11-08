import { FAQ } from "@/content";

export function Faq() {
  return (
    <section id="faq" aria-labelledby="faq-h" className="mx-auto max-w-[1440px] px-4 py-16 sm:px-8 lg:py-24">
      <h2 id="faq-h" className="display text-[32px] sm:text-[40px]">
        {FAQ.title}
      </h2>
      <div className="mt-10 max-w-[760px]">
        {FAQ.items.map((f) => (
          <details key={f.q} className="group border-t-2 border-black last:border-b-2">
            <summary className="flex cursor-pointer list-none items-center justify-between gap-4 py-4 text-[18px] font-medium">
              {f.q}
              <span aria-hidden="true" className="font-mono text-[20px] leading-none group-open:hidden">
                +
              </span>
              <span aria-hidden="true" className="hidden font-mono text-[20px] leading-none group-open:inline">
                −
              </span>
            </summary>
            <p className="max-w-[60ch] pb-5 text-ink-2">{f.a}</p>
          </details>
        ))}
      </div>
    </section>
  );
}
