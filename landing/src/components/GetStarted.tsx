import { CTA } from "@/content";
import { Button } from "./Button";
import { CopyCommand } from "./CopyCommand";
import { Frame } from "./Frame";

export function GetStarted() {
  return (
    <section id={CTA.id} aria-labelledby="cta-title" className="border-b border-line">
      <Frame>
        <div className="px-4 py-12 sm:px-8 lg:px-12 lg:py-16">
          <div className="on-dark rounded-xl bg-forest px-6 py-12 text-mist sm:px-10 lg:px-14 lg:py-16">
            <h2
              id="cta-title"
              className="max-w-[22ch] text-balance text-4xl font-medium leading-[1.05] tracking-[-0.035em] text-white sm:text-5xl lg:text-[56px]"
            >
              {CTA.title}
            </h2>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <Button href={CTA.primary.href}>{CTA.primary.label}</Button>
              <Button href={CTA.secondary.href} variant="dark-outline">
                {CTA.secondary.label}
              </Button>
            </div>
            <div className="mt-8">
              <CopyCommand />
            </div>
          </div>
        </div>
      </Frame>
    </section>
  );
}
