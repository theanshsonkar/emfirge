import { SquareTerminal } from "lucide-react";
import { CTA, FOOTER } from "@/content";
import { H2 } from "./Heading";
import { LogoMark } from "./Logo";

export function FinalCta() {
  return (
    <section data-nav="faq" className="px-4 pb-14 pt-4 text-center md:pb-16">
      <H2 className="mx-auto max-w-[560px] text-[32px] leading-[1.12] md:text-[40px] md:leading-[1.1]">{CTA.title}</H2>
      <a
        href={CTA.button.href}
        className="mt-8 inline-flex h-12 items-center gap-2 rounded-full bg-ink px-6 text-[16px] font-medium tracking-[-0.01em] text-white transition-opacity hover:opacity-85"
      >
        <SquareTerminal size={18} aria-hidden="true" />
        {CTA.button.label}
      </a>
    </section>
  );
}

export function Footer() {
  return (
    <footer className="relative overflow-hidden px-4 pt-10 text-center text-[12px] leading-[18px] text-ink-3">
      <nav aria-label="Footer" className="flex flex-wrap items-center justify-center gap-x-4 gap-y-1">
        {FOOTER.links.map((l) => (
          <a key={l.label} href={l.href} className="underline underline-offset-[3px] hover:text-ink">
            {l.label}
          </a>
        ))}
      </nav>
      <p className="mt-3">
        {FOOTER.copy} ·{" "}
        <a href={FOOTER.built.href} className="underline underline-offset-[3px] hover:text-ink">
          {FOOTER.built.pre}
          {FOOTER.built.heart}
        </a>
      </p>
      <div aria-hidden="true" className="pointer-events-none mx-auto mt-10 h-[150px] w-[300px] overflow-hidden md:h-[190px] md:w-[380px]">
        <LogoMark size={380} className="h-[300px] w-[300px] text-black/[0.045] md:h-[380px] md:w-[380px]" />
      </div>
    </footer>
  );
}
