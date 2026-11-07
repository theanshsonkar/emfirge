import { Lock, SquareTerminal } from "lucide-react";
import { HERO, HERO_SCRIPT } from "@/content";
import { HandNote, HeroToast } from "./HeroFloaters";
import { LogoMark } from "./Logo";
import { MacWindow } from "./MacWindow";
import { TerminalScript } from "./TerminalScript";

export function Hero() {
  return (
    <section id="top" data-nav="top" className="relative px-4 pt-14 md:pt-[72px]">
      <div className="mx-auto flex max-w-[720px] flex-col items-center text-center">
        <h1 className="text-[40px] font-semibold leading-[1.05] tracking-[-0.045em] text-ink md:text-[48px]">
          <em>{HERO.lead}</em>{" "}
          <LogoMark size={40} className="inline-block h-[0.82em] w-[0.82em] -translate-y-[0.02em] align-baseline" />{" "}
          {HERO.name}.
        </h1>
        <p className="mt-5 text-[17px] leading-[26px] text-ink-2 md:text-[18px]">
          <strong className="font-semibold text-ink">{HERO.subA[0]}</strong>
          {HERO.subA[1]}
          <br />
          <strong className="font-semibold text-ink">{HERO.subB[0]}</strong>
          {HERO.subB[1]}
        </p>
        <a
          href={HERO.cta.href}
          className="mt-7 inline-flex h-12 items-center gap-2 rounded-full bg-ink px-6 text-[16px] font-medium tracking-[-0.01em] text-white transition-opacity hover:opacity-85"
        >
          <SquareTerminal size={18} strokeWidth={2} aria-hidden="true" />
          {HERO.cta.label}
        </a>
        <p className="mt-5 text-[12px] leading-[18px] text-ink-3">{HERO.meta}</p>
        <p className="mt-1 inline-flex items-center gap-1.5 text-[12px] leading-[18px] text-ink-3">
          <Lock size={12} aria-hidden="true" />
          {HERO.lock}
        </p>
        <p className="mt-6 inline-flex items-center gap-2 text-[12px] leading-[18px] text-ink-3">
          <span
            aria-hidden="true"
            className="flex h-[18px] w-[18px] items-center justify-center rounded-full bg-black/[0.08] text-[11px] font-medium leading-none text-ink-2"
          >
            a
          </span>
          <span>
            {HERO.built.pre}
            <a href={HERO.built.href} className="font-semibold text-ink">
              {HERO.built.name}
            </a>
          </span>
        </p>
      </div>

      <div className="relative mx-auto mt-12 w-full max-w-[780px] md:mt-16">
        <MacWindow variant="terminal" title="~/infra — zsh">
          <TerminalScript lines={HERO_SCRIPT} animate className="min-h-[300px] md:min-h-[400px]" />
        </MacWindow>
        <HandNote />
      </div>
      <HeroToast />
    </section>
  );
}
