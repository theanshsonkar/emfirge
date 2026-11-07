import { Section, H2 } from "./ui/Section";
import { SignalCard } from "./ui/SignalCard";
import { SIGNAL } from "@/content";

export function Facts() {
  return (
    <Section aria-labelledby="facts-h">
      <div className="grid items-center gap-12 lg:grid-cols-2 lg:gap-16">
        <div>
          <H2 id="facts-h">Signals are facts. Your agent does the thinking.</H2>
          <p className="mt-6 max-w-[52ch] text-lg leading-relaxed text-muted">
            Emfirge has no AI inside. It&apos;s deterministic: the same branch always gives the same answer, and it
            can&apos;t be talked into a pass. A change it can&apos;t model never passes; it says what it couldn&apos;t
            check.
          </p>
        </div>
        <SignalCard {...SIGNAL} status="FAIL" />
      </div>
    </Section>
  );
}
