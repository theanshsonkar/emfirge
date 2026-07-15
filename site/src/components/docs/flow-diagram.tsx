import { GitBranch, PencilLine, Gauge, GitCompareArrows, ShieldCheck, ChevronRight } from "lucide-react";

const STEPS = [
  { n: 1, icon: GitBranch, title: "Clone", sub: "Deep-copy the scanned graph in memory" },
  { n: 2, icon: PencilLine, title: "Mutate", sub: "Apply the proposed change on the clone" },
  { n: 3, icon: Gauge, title: "Re-score", sub: "Re-run every rule, context-aware" },
  { n: 4, icon: GitCompareArrows, title: "Diff", sub: "Findings removed / added + score delta" },
];

/**
 * Monochrome fork-flow diagram: clone → mutate → re-score → diff → proven.
 * Server component, theme-aware via CSS vars, responsive (row on md+, stack on mobile).
 */
export function ForkFlow() {
  return (
    <figure className="ticks my-8 rounded-md border border-border bg-surface p-5">
      <figcaption className="tag mb-4">the fork, end to end</figcaption>

      <div className="flex flex-col gap-2 md:flex-row md:items-stretch">
        {STEPS.map((s, i) => (
          <div key={s.n} className="flex items-stretch gap-2 md:flex-1">
            <div className="flex-1 rounded-lg border border-border bg-surface-2 p-3.5">
              <div className="flex items-center gap-2">
                <span className="flex size-6 shrink-0 items-center justify-center rounded-md bg-accent font-mono text-[12px] font-medium text-foreground">
                  {s.n}
                </span>
                <s.icon className="size-4 text-muted-foreground" />
                <span className="text-[13.5px] font-medium text-foreground">{s.title}</span>
              </div>
              <p className="mt-2 text-[12px] leading-relaxed text-muted-foreground">{s.sub}</p>
            </div>
            {i < STEPS.length - 1 && (
              <div className="flex items-center justify-center text-border md:px-0.5" aria-hidden>
                <ChevronRight className="size-4 rotate-90 md:rotate-0" />
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="mt-3 flex items-center gap-2 rounded-lg border border-safe/25 bg-accent/20 px-3.5 py-2.5">
        <ShieldCheck className="size-4 shrink-0" style={{ color: "var(--safe)" }} />
        <span className="text-[12.5px] text-muted-foreground">
          Runs entirely on the saved graph in memory, <span className="font-medium text-foreground">your live AWS account is never touched</span>.
        </span>
      </div>
    </figure>
  );
}
