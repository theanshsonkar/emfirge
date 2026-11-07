import { WALL } from "@/content";
import { H2 } from "./Heading";

function XMark() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" aria-hidden="true" className="shrink-0 text-black/35">
      <path
        fill="currentColor"
        d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"
      />
    </svg>
  );
}

/** A tweet-style card that is clearly a placeholder: dashed edge, gray avatar, the word "placeholder". */
export function TweetPlaceholder() {
  const c = WALL.card;
  return (
    <figure className="relative flex h-[168px] w-[272px] shrink-0 flex-col justify-between rounded-2xl bg-surface p-5 text-left sm:w-[320px]">
      <span
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 rounded-2xl border border-dashed border-black/20"
      />
      <span className="absolute right-4 top-4 rounded-md bg-black/[0.06] px-1.5 py-0.5 text-[11px] font-medium leading-[14px] text-ink-2">
        {c.chip}
      </span>
      <blockquote className="pr-20 text-[16px] leading-6 text-ink">{c.text}</blockquote>
      <figcaption className="flex items-center gap-2.5">
        <span aria-hidden="true" className="h-8 w-8 shrink-0 rounded-full bg-black/[0.07]" />
        <span className="min-w-0 flex-1 text-[13px] leading-[17px]">
          <span className="block font-medium text-ink">{c.name}</span>
          <span className="block text-ink-3">{c.handle}</span>
        </span>
        <XMark />
      </figcaption>
    </figure>
  );
}

export function Tweets() {
  const row = Array.from({ length: WALL.count / 2 });
  return (
    <section id="love" data-nav="why" className="pb-[88px] md:pb-[120px]">
      <div className="px-4">
        <H2>{WALL.title}</H2>
        <p className="mx-auto mt-3 max-w-[520px] text-center text-[16px] leading-6 text-ink-2">
          {WALL.lead}{" "}
          <a href={WALL.link.href} className="font-medium text-ink underline underline-offset-[3px]">
            {WALL.link.label}
          </a>
        </p>
      </div>
      <div
        className="no-scrollbar mx-auto mt-10 max-w-[1100px] overflow-x-auto px-4"
        style={{
          maskImage: "linear-gradient(to right, transparent 0, #000 56px, #000 calc(100% - 56px), transparent 100%)",
        }}
        tabIndex={0}
        aria-label="placeholder testimonials, scroll sideways"
      >
        <div className="flex w-max flex-col gap-4">
          <div className="flex gap-4">
            {row.map((_, i) => (
              <TweetPlaceholder key={i} />
            ))}
          </div>
          <div className="ml-[148px] flex gap-4 sm:ml-[168px]">
            {row.map((_, i) => (
              <TweetPlaceholder key={i} />
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
