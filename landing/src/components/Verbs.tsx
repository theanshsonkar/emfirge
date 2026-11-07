import { Section, Eyebrow, H2 } from "./ui/Section";
import { VerbCard } from "./ui/VerbCard";
import { VERBS } from "@/content";

export function Verbs() {
  return (
    <Section id="verbs" aria-labelledby="verbs-h">
      <Eyebrow>The CLI</Eyebrow>
      <H2 id="verbs-h" className="max-w-[20ch]">Six verbs. Every agent already knows how to use them.</H2>
      <p className="mt-5 max-w-[56ch] text-lg text-muted">
        No SDK, no plugin. If your agent can run a shell command, it can work on your cloud.
      </p>
      <div className="mt-12 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {VERBS.map((v) => (
          <VerbCard key={v.name} verb={v} />
        ))}
      </div>
    </Section>
  );
}
