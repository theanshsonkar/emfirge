import { Terminal } from "./Terminal";
import { Container } from "./ui/Container";
import { CommandBox } from "./ui/CommandBox";
import { ButtonLink } from "./ui/Button";
import { CONNECT_CMD, LINKS } from "@/content";

export function Hero() {
  return (
    <section id="top" className="relative overflow-hidden pb-16 pt-14 md:pb-24 md:pt-24">
      <div aria-hidden="true" className="dot-grid pointer-events-none absolute inset-0" />
      <Container className="relative">
        <p className="inline-flex items-center gap-2 rounded-full border border-line bg-surface px-3.5 py-1.5 font-mono text-xs text-paper">
          <span className="text-forge" aria-hidden="true">●</span> emfirge cli v1 · AWS
        </p>
        <h1 className="mt-6 max-w-[14ch] font-display text-[48px] leading-[0.98] tracking-[-0.02em] md:max-w-[16ch] md:text-[88px]">
          The harness for <em className="text-forge">cloud</em> agents.
        </h1>
        <p className="mt-6 max-w-[62ch] text-base leading-relaxed text-muted md:text-lg">
          Your coding agent has files, a branch, tests and a log. Emfirge gives it the same when it touches your
          cloud: a true model of your AWS, a branch to try changes on, and facts about what would break, before
          anything reaches production.
        </p>
        <div className="mt-8 flex flex-col gap-4 sm:flex-row sm:items-center">
          <CommandBox command={CONNECT_CMD} className="sm:w-auto sm:min-w-[400px]" />
          <ButtonLink href={LINKS.docs} variant="ghost">Read the docs →</ButtonLink>
        </div>
        <p className="mt-4 text-sm text-muted">Read-only. Works with any agent that can run a shell.</p>
        <div className="mx-auto mt-14 max-w-[920px] md:mt-20">
          <Terminal />
        </div>
      </Container>
    </section>
  );
}
