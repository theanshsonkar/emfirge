import { Section, H2 } from "./ui/Section";
import { ButtonLink } from "./ui/Button";
import { LINKS, STEPS } from "@/content";

export function GetStarted() {
  return (
    <Section id="get-started" aria-labelledby="start-h">
      <H2 id="start-h" className="max-w-[18ch]">Two minutes to a safe cloud agent.</H2>
      <ol className="mt-12 grid gap-4 md:grid-cols-3">
        {STEPS.map((s, i) => (
          <li key={i} className="rounded-[14px] border border-line bg-surface p-6">
            <span className="font-mono text-sm text-forge">{String(i + 1).padStart(2, "0")}</span>
            <p className="mt-4 leading-relaxed text-paper">
              {s.cmd && <code className="break-all font-mono text-[13px] text-forge">{s.cmd}</code>}
              {s.cmd && ": "}
              {s.text}
            </p>
          </li>
        ))}
      </ol>
      <div className="mt-10 flex flex-wrap gap-3">
        <ButtonLink href="#get-started">Get started</ButtonLink>
        <ButtonLink href={LINKS.docs} variant="ghost">Read the docs</ButtonLink>
      </div>
    </Section>
  );
}
