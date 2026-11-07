import { Section, H2, Eyebrow } from "./ui/Section";
import { Rich } from "./ui/Rich";
import { Frame } from "./ui/Frame";
import { CONNECT_CMD, START } from "@/content";

function MiniCommand() {
  return (
    <div className="rounded-lg border border-white/10 bg-black/40 px-3 py-2.5 font-mono text-[11.5px] text-paper">
      <span className="text-muted">$ </span>
      <span className="break-all">{CONNECT_CMD}</span>
    </div>
  );
}
function MiniStack() {
  return (
    <div className="rounded-lg border border-white/10 bg-black/40 px-3 py-2.5 font-mono text-[11.5px]">
      <p className="text-muted">CloudFormation · stack</p>
      <p className="mt-1 flex items-center justify-between gap-2">
        <span className="text-paper">emfirge-readonly</span>
        <span className="rounded-full border border-pass/40 bg-pass/10 px-2 py-px text-[10px] text-pass">CREATE_COMPLETE</span>
      </p>
    </div>
  );
}
function MiniChat() {
  return (
    <div className="rounded-lg border border-white/10 bg-black/40 px-3 py-2.5 text-[13px] leading-snug text-paper">
      <span className="font-mono text-xs text-muted">you › </span>&ldquo;{START.prompt}&rdquo;
    </div>
  );
}

export function GetStarted() {
  const visuals = [<MiniCommand key="a" />, <MiniStack key="b" />, <MiniChat key="c" />];
  return (
    <Section id="get-started" aria-labelledby="start-h" className="pb-12 md:pb-16">
      <div className="mx-auto max-w-[760px] text-center">
        <Eyebrow>Get started</Eyebrow>
        <H2 id="start-h">
          <Rich text={START.h2} />
        </H2>
      </div>
      <ol className="relative mt-14 grid gap-5 md:grid-cols-3 md:gap-6">
        {/* dashed connector */}
        <span
          aria-hidden="true"
          className="absolute left-[16.6%] right-[16.6%] top-[44px] hidden border-t border-dashed border-forge/50 md:block"
        />
        <span aria-hidden="true" className="absolute bottom-10 left-[43px] top-10 border-l border-dashed border-forge/50 md:hidden" />
        {START.steps.map((s, i) => (
          <li key={s.title} className="relative">
            <Frame radius={20} hover className="h-full" innerClassName="bg-[#0f0f11] h-full">
              <div className="p-6 pl-[84px] md:pl-6">
                <span className="absolute left-5 top-5 flex size-12 items-center justify-center rounded-full border border-forge/50 bg-[#0b0b0c] font-mono text-lg text-forge shadow-[0_0_24px_-4px_rgba(255,90,31,0.6)] md:static md:mb-5">
                  {i + 1}
                </span>
                <h3 className="font-display text-[28px] leading-none tracking-[-0.01em]">{s.title}</h3>
                <p className="mb-5 mt-3 text-[14.5px] leading-relaxed text-muted">{s.text}</p>
                {visuals[i]}
              </div>
            </Frame>
          </li>
        ))}
      </ol>
    </Section>
  );
}
