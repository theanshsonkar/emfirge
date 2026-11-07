import { Section, H2 } from "./ui/Section";
import { CodeCard } from "./ui/CodeCard";
import { EMFIRGE_MD } from "@/content";

export function EmfirgeMd() {
  return (
    <Section aria-labelledby="md-h" className="pt-0 md:pt-0">
      <div className="grid items-center gap-12 lg:grid-cols-2 lg:gap-16">
        <CodeCard title="emfirge.md" className="order-2 lg:order-1">
          {EMFIRGE_MD.map((l, i) => (
            <p key={l} className={i === 0 ? "text-muted" : "text-paper"}>{l}</p>
          ))}
        </CodeCard>
        <div className="order-1 lg:order-2">
          <H2 id="md-h">Write your intent once. Every agent reads it.</H2>
          <p className="mt-6 max-w-[48ch] text-lg leading-relaxed text-muted">
            Plain English. Agents read it as context; Emfirge enforces the hard lines as boundaries.
          </p>
        </div>
      </div>
    </Section>
  );
}
