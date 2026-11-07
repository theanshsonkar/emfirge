import { CloudCanvas } from "./CloudCanvas";
import { Container } from "./ui/Container";
import { CommandBox } from "./ui/CommandBox";
import { ButtonLink } from "./ui/Button";
import { CONNECT_CMD, HERO, LINKS } from "@/content";

export function Hero() {
  return (
    <section id="top" className="relative overflow-hidden pb-16 pt-[96px] md:pb-24 md:pt-[104px]">
      {/* depth: plum + forge glows, dot grid */}
      <div aria-hidden="true" className="pointer-events-none absolute inset-0">
        <div className="absolute left-1/2 top-[-260px] h-[720px] w-[1100px] -translate-x-1/2 bg-[radial-gradient(closest-side,rgba(42,22,48,0.95),transparent)]" />
        <div className="absolute left-1/2 top-[-120px] h-[420px] w-[760px] -translate-x-[10%] bg-[radial-gradient(closest-side,rgba(255,90,31,0.16),transparent)]" />
        <div className="dot-grid absolute inset-0 opacity-70" />
      </div>

      <Container className="relative max-w-[1240px]">
        <div className="flex flex-col items-center text-center">
          <p className="glass inline-flex items-center gap-2 rounded-full border border-white/10 px-3.5 py-1.5 font-mono text-xs text-paper">
            <span className="text-forge" aria-hidden="true">●</span> {HERO.eyebrow}
          </p>
          <h1 className="mt-5 max-w-[17ch] font-display text-[clamp(50px,8.2vw,104px)] leading-[0.96] tracking-[-0.02em] text-balance md:max-w-none">
            The harness for <em className="text-forge">cloud</em> agents.
          </h1>
          <p className="mt-4 max-w-[58ch] text-base leading-relaxed text-muted md:text-[18px]">{HERO.sub}</p>
          <div className="mt-6 flex w-full flex-col items-center gap-3 sm:w-auto sm:flex-row">
            <CommandBox command={CONNECT_CMD} className="sm:w-auto sm:min-w-[400px]" />
            <ButtonLink href={LINKS.docs} variant="ghost" className="w-full sm:w-auto">
              Read the docs →
            </ButtonLink>
          </div>
        </div>

        <div className="relative mt-9 md:mt-10">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute -inset-x-10 -bottom-24 top-1/3 bg-[radial-gradient(50%_55%_at_30%_100%,rgba(255,90,31,0.32),transparent),radial-gradient(45%_55%_at_75%_100%,rgba(90,40,110,0.55),transparent)] blur-2xl"
          />
          <CloudCanvas />
        </div>
      </Container>
    </section>
  );
}
