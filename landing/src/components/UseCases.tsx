import { Section, Eyebrow, H2 } from "./ui/Section";
import { Card } from "./ui/Card";
import { USE_CASES } from "@/content";

export function UseCases() {
  return (
    <Section aria-labelledby="uses-h">
      <Eyebrow>Use cases</Eyebrow>
      <H2 id="uses-h">Your agent invents the uses.</H2>
      <ul className="mt-12 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {USE_CASES.map((u) => (
          <li key={u.name}>
            <Card className="h-full px-5 py-4">
              <h3 className="font-semibold">{u.name}</h3>
              <p className="mt-1 text-[15px] text-muted">{u.line}</p>
            </Card>
          </li>
        ))}
      </ul>
    </Section>
  );
}
