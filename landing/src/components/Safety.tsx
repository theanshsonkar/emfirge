import { Section, Eyebrow, H2 } from "./ui/Section";
import { Card } from "./ui/Card";
import { Rich } from "./ui/Rich";
import { SAFETY } from "@/content";

export function Safety() {
  return (
    <Section id="safety" aria-labelledby="safety-h">
      <Eyebrow>Safety</Eyebrow>
      <H2 id="safety-h">Built to be trusted.</H2>
      <div className="mt-12 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {SAFETY.map((s) => (
          <Card key={s.title} className="p-6">
            <h3 className="text-lg font-semibold">{s.title}</h3>
            <p className="mt-2 leading-relaxed text-muted"><Rich text={s.body} /></p>
          </Card>
        ))}
      </div>
    </Section>
  );
}
