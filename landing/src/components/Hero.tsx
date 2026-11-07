import { HERO } from "@/content";
import { Button } from "./Button";
import { CopyCommand } from "./CopyCommand";
import { Frame } from "./Frame";
import { HeroFork } from "./HeroFork";
import { HeroGraph } from "./HeroGraph";

export function Hero() {
  return (
    <section id="top" className="border-b border-line">
      <Frame>
        <div className="on-dark bg-forest text-mist">
          <div className="lg:grid lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)] lg:items-center lg:gap-8 lg:px-12 lg:py-14">
          <div className="px-4 pb-10 pt-14 sm:px-8 sm:pt-20 lg:px-0 lg:py-0">
            <h1 className="max-w-[18ch] text-balance text-[44px] font-medium leading-[1.02] tracking-[-0.035em] text-white sm:text-6xl lg:text-[72px]">
              {HERO.title}
            </h1>
            <p className="mt-6 max-w-[56ch] text-base leading-[1.6] text-mist sm:text-lg">{HERO.body}</p>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <Button href={HERO.primary.href}>{HERO.primary.label}</Button>
              <Button href={HERO.secondary.href} variant="dark-outline">
                {HERO.secondary.label}
              </Button>
            </div>
            <div className="mt-8">
              <CopyCommand />
            </div>
          </div>
          <HeroGraph />
          </div>
          <HeroFork />
          <div className="h-6" />
        </div>
      </Frame>
    </section>
  );
}
