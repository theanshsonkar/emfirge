import { GitBranch, Terminal } from "lucide-react";
import { SPLIT, type TermLine } from "@/content";
import { cn } from "@/lib/cn";
import { ConsoleLog } from "./ConsoleLog";
import { Frame } from "./Frame";

const tone: Record<TermLine["tone"], string> = {
  cmd: "text-white",
  out: "text-mist-2",
  block: "text-block-on-dark",
  pass: "text-pass-on-dark",
};

function Chrome({ title }: { title?: string }) {
  return (
    <div className="flex items-center gap-1.5 border-b border-forest-line px-4 py-3" aria-hidden="true">
      <span className="h-2.5 w-2.5 rounded-full bg-trunk" />
      <span className="h-2.5 w-2.5 rounded-full bg-trunk" />
      <span className="h-2.5 w-2.5 rounded-full bg-trunk" />
      {title && <span className="ml-auto font-mono text-xs text-mist-2">{title}</span>}
    </div>
  );
}

export function SplitPanel() {
  const { agent, branch } = SPLIT;
  return (
    <section id={SPLIT.id} aria-labelledby="split-title" className="border-b border-line bg-white">
      <Frame>
        <div className="px-4 pb-8 pt-16 sm:px-8 lg:px-12 lg:pt-24">
          <h2
            id="split-title"
            className="max-w-[22ch] text-balance text-4xl font-medium leading-[1.05] tracking-[-0.035em] text-ink sm:text-5xl lg:text-[56px]"
          >
            {SPLIT.title}
          </h2>
          <p className="mt-6 max-w-[60ch] text-base text-ink-2">{SPLIT.body}</p>
        </div>

        <div className="px-4 pb-16 sm:px-8 lg:px-12 lg:pb-24">
          <div className="grid overflow-hidden rounded-xl border border-line lg:grid-cols-2">
            <div className="bg-white p-5 sm:p-8">
              <p className="flex items-center gap-2 text-sm font-medium text-brand">
                <Terminal size={16} aria-hidden="true" />
                {agent.label}
              </p>
              <h3 className="mt-3 text-[22px] font-medium leading-[1.3] tracking-[-0.02em] text-ink">{agent.title}</h3>
              <div
                role="img"
                aria-label={agent.mockLabel}
                className="mt-8 overflow-hidden rounded-xl bg-forest-deep shadow-mock"
              >
                <Chrome title={agent.path} />
                <div className="min-h-[220px] space-y-1 px-4 py-4 font-mono text-[13px] leading-6" aria-hidden="true">
                  {agent.lines.map((l) => (
                    <p key={l.text} className={cn("break-words", tone[l.tone], l.tone !== "cmd" && "pl-4")}>
                      {l.tone === "cmd" && <span className="mr-2 select-none text-mist-2">$</span>}
                      {l.text}
                    </p>
                  ))}
                </div>
              </div>
            </div>

            <div className="on-dark bg-forest p-5 sm:p-8">
              <p className="flex items-center gap-2 text-sm font-medium text-mist">
                <GitBranch size={16} aria-hidden="true" />
                {branch.label}
              </p>
              <h3 className="mt-3 text-[22px] font-medium leading-[1.3] tracking-[-0.02em] text-white">{branch.title}</h3>
              <div className="mt-8 overflow-hidden rounded-xl border border-forest-line bg-forest-deep">
                <Chrome />
                <p className="sr-only">{branch.mockLabel}</p>
                <ConsoleLog />
              </div>
            </div>
          </div>
        </div>
      </Frame>
    </section>
  );
}
