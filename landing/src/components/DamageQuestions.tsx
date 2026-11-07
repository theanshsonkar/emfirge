import { Section, Eyebrow, H2 } from "./ui/Section";
import { Card } from "./ui/Card";
import { DAMAGE_QUESTIONS } from "@/content";

export function DamageQuestions() {
  return (
    <Section aria-labelledby="damage-h">
      <Eyebrow>Signals</Eyebrow>
      <H2 id="damage-h" className="max-w-[22ch]">Six questions about the result. Not 15,000 rules about actions.</H2>
      <p className="mt-5 max-w-[60ch] text-lg text-muted">
        Emfirge doesn&apos;t judge what an agent says it&apos;s doing. It judges what the change does on the branch.
      </p>
      <div className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {DAMAGE_QUESTIONS.map((q) => (
          <Card key={q.name} className="p-6">
            <q.icon size={22} className="text-forge" aria-hidden="true" />
            <h3 className="mt-4 text-lg font-semibold">{q.name}</h3>
            <p className="mt-1.5 leading-relaxed text-muted">{q.question}</p>
          </Card>
        ))}
      </div>
      <p className="mt-10 max-w-[62ch] text-lg text-muted">
        Each answer either <strong className="font-semibold text-paper">tells</strong> you (a line in the record,
        nobody waits) or <strong className="font-semibold text-paper">asks</strong> you (your agent keeps working on
        something else).
      </p>
    </Section>
  );
}
