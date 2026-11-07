import { Section, Eyebrow, H2 } from "./ui/Section";
import { Card } from "./ui/Card";
import { Rich } from "./ui/Rich";
import { PROBLEMS } from "@/content";

export function Problem() {
  return (
    <Section aria-labelledby="problem-h">
      <Eyebrow>The problem</Eyebrow>
      <H2 id="problem-h" className="max-w-[20ch]">Nobody trusts an agent with their cloud. For good reason.</H2>
      <div className="mt-12 grid gap-4 md:grid-cols-3">
        {PROBLEMS.map((p) => (
          <Card key={p.title} className="p-6">
            <p.icon size={22} className="text-forge" aria-hidden="true" />
            <h3 className="mt-5 text-lg font-semibold">{p.title}</h3>
            <p className="mt-2 leading-relaxed text-muted"><Rich text={p.body} /></p>
          </Card>
        ))}
      </div>
    </Section>
  );
}
