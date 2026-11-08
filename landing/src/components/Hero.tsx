import { HERO } from "@/content";
import { Bench } from "./Bench";
import { CopyCommand } from "./CopyCommand";

export function Hero() {
  return (
    <section id="top" aria-labelledby="h1" className="mx-auto max-w-[1440px] px-4 pb-16 pt-6 sm:px-8 lg:pb-24">
      <div className="grid grid-cols-[minmax(0,1fr)] gap-10 lg:grid-cols-[minmax(0,5fr)_minmax(0,8fr)] lg:gap-12 xl:grid-cols-[minmax(0,4fr)_minmax(0,9fr)] xl:gap-8">
        <div className="lg:sticky lg:top-[72px] lg:self-start lg:pt-6">
          <h1 id="h1" className="display text-[40px] sm:text-[56px] lg:text-[64px] xl:text-[56px]">
            {HERO.h1}
          </h1>
          <p className="mt-6 max-w-[34em] text-[17px]">{HERO.body}</p>
          <p className="mb-2.5 mt-8 text-[14px] text-ink-2">{HERO.then}</p>
          <CopyCommand />
        </div>
        <Bench />
      </div>
    </section>
  );
}
