import { QUESTIONS, SIX } from "@/content";

export function Questions() {
  return (
    <section aria-labelledby="six-h" className="mx-auto max-w-[1440px] px-4 py-16 sm:px-8 lg:py-24">
      <h2 id="six-h" className="display text-[32px] sm:text-[40px]">
        {SIX.title}
      </h2>
      <ul className="mt-12 grid grid-cols-[minmax(0,1fr)] gap-x-12 gap-y-10 sm:grid-cols-2">
        {QUESTIONS.map((q) => (
          <li key={q.id} className="border-t-2 border-black pt-4">
            <h3 className="text-[22px] font-bold leading-tight">{q.name}</h3>
            <p className="mt-2 max-w-[32em] text-ink-2">{q.sentence}</p>
          </li>
        ))}
      </ul>
      <p className="mt-12 flex items-start gap-3 text-[17px]">
        <span aria-hidden="true" className="mt-[7px] size-3.5 shrink-0 rounded-[3px] bg-crash" />
        {SIX.note}
      </p>
    </section>
  );
}
