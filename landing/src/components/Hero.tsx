import { HERO } from "@/content";
import { Button } from "./Button";
import { CopyCommand } from "./CopyCommand";
import { Frame } from "./Frame";
import { HeroFork } from "./HeroFork";

export function Hero() {
  return (
    <section id="top" className="border-b border-line">
      <Frame>
        <div className="on-dark bg-forest text-mist">
          <div className="px-4 pb-10 pt-14 sm:px-8 sm:pt-20 lg:px-12 lg:pt-24">
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
          <HeroFork />
          <div className="h-6" />
        </div>
      </Frame>
    </section>
  );
}
