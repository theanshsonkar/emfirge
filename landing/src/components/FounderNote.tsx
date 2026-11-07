import { NOTE } from "@/content";
import { H2 } from "./Heading";
import { MacWindow } from "./MacWindow";

function Para({ text }: { text: string }) {
  const parts = text.split(/==/);
  return (
    <p>
      {parts.map((p, i) =>
        i % 2 ? (
          <mark
            key={i}
            className="rounded-[3px] bg-hl px-[3px] text-ink [box-decoration-break:clone]"
          >
            {p}
          </mark>
        ) : (
          p
        ),
      )}
    </p>
  );
}

export function FounderNote() {
  const a = NOTE.author;
  return (
    <section id="story" data-nav="why" className="px-4 pb-[88px] md:pb-[120px]">
      <H2>{NOTE.title}</H2>
      <div className="mx-auto mt-10 w-full max-w-[560px]">
        <MacWindow variant="notes" title={NOTE.app}>
          <article className="px-5 pb-6 pt-6 text-[16px] leading-[27px] text-ink-2 sm:px-8 sm:pb-7 sm:pt-7 sm:text-[17px] sm:leading-[29px]">
            <div className="space-y-4 sm:space-y-[18px]">
              {NOTE.paragraphs.map((t) => (
                <Para key={t} text={t} />
              ))}
            </div>
            <footer className="mt-7 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span
                  aria-hidden="true"
                  className="flex h-11 w-11 items-center justify-center rounded-full bg-black/[0.07] text-[18px] font-medium text-ink-2"
                >
                  {a.initial}
                </span>
                <span className="text-[14px] leading-[19px]">
                  <span className="block text-ink">{a.name}</span>
                  <span className="block text-ink-3">{a.role}</span>
                </span>
              </div>
              <span className="-rotate-3 font-hand text-[40px] leading-none text-ink" aria-label={`signed ${NOTE.signature}`}>
                {NOTE.signature}
              </span>
            </footer>
          </article>
        </MacWindow>
      </div>
    </section>
  );
}
