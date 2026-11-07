import { Section } from "./ui/Section";
import { AGENTS } from "@/content";

export function WorksWith() {
  return (
    <Section aria-label="Compatible agents" className="border-y border-line py-10 md:py-10">
      <div className="text-center">
        <p className="text-sm text-muted">Works with any agent that runs a shell</p>
        <ul className="mt-4 flex flex-wrap justify-center gap-x-2 gap-y-1 text-lg text-paper">
          {AGENTS.map((a, i) => (
            <li key={a} className="flex items-center gap-2">
              {i > 0 && <span className="text-muted" aria-hidden="true">·</span>}
              {a}
            </li>
          ))}
        </ul>
      </div>
    </Section>
  );
}
