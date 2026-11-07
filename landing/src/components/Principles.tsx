import { PRINCIPLES } from "@/content";
import { Frame } from "./Frame";

export function Principles() {
  return (
    <section aria-labelledby="principles-title" className="border-b border-line">
      <Frame>
        <div className="px-4 py-16 sm:px-8 lg:px-12 lg:py-24">
          <h2
            id="principles-title"
            className="max-w-[22ch] text-balance text-4xl font-medium leading-[1.05] tracking-[-0.035em] text-ink sm:text-5xl lg:text-[56px]"
          >
            {PRINCIPLES.title}
          </h2>
          <ul className="mt-12 grid gap-10 md:grid-cols-3 md:gap-8">
            {PRINCIPLES.items.map((p) => (
              <li key={p.title} className="border-t border-line pt-5">
                <h3 className="text-[22px] font-medium leading-[1.3] tracking-[-0.02em] text-ink">{p.title}</h3>
                <p className="mt-3 max-w-[40ch] text-base text-ink-2">{p.body}</p>
              </li>
            ))}
          </ul>
        </div>
      </Frame>
    </section>
  );
}
