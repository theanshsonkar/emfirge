import { Cloud, GitBranch, ShieldCheck, Sparkles } from "lucide-react";

/** The core Emfirge story, shared by the overview and concept docs. */
export function HarnessDiagram() {
  return (
    <figure className="ticks relative my-8 min-w-0 max-w-full overflow-hidden rounded-xl border border-border bg-surface p-5 sm:p-6">
      <div className="pointer-events-none absolute inset-0 grid-motif opacity-40 [mask-image:linear-gradient(to_bottom,black,transparent_90%)]" aria-hidden />
      <figcaption className="tag relative mb-5">the harness layer</figcaption>
      <div className="relative grid min-w-0 max-w-full grid-cols-1 gap-3 md:grid-cols-[minmax(0,1fr)_auto_minmax(0,1.2fr)_auto_minmax(0,1fr)] md:items-center">
        <div className="rounded-lg border border-border bg-surface-2 p-4">
          <div className="flex items-center gap-2 text-foreground">
            <Sparkles className="size-4" style={{ color: "var(--safe)" }} />
            <span className="font-medium">AI agent</span>
          </div>
          <p className="mt-2 text-[12px] leading-relaxed text-muted-foreground">Proposes the next cloud change.</p>
        </div>
        <div className="flex justify-center text-muted-foreground" aria-hidden>
          <span className="hidden text-lg md:inline">→</span><span className="text-lg md:hidden">↓</span>
        </div>
        <div className="relative rounded-xl border border-safe/45 bg-accent/45 p-4 shadow-[0_0_0_4px_color-mix(in_oklab,var(--safe)_8%,transparent)]">
          <div className="flex items-center gap-2 text-foreground">
            <GitBranch className="size-4" style={{ color: "var(--safe)" }} />
            <span className="font-display font-semibold">Emfirge</span>
            <span className="rounded-full border border-safe/30 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-[0.16em] text-muted-foreground">harness</span>
          </div>
          <p className="mt-2 text-[12px] leading-relaxed text-muted-foreground">Forks, models, measures, and returns a verdict before anything is real.</p>
          <div className="mt-3 flex items-center gap-1.5 font-mono text-[10px] text-muted-foreground">
            <span className="rounded border border-border bg-surface px-1.5 py-1">branch</span>
            <span>+</span>
            <span className="rounded border border-border bg-surface px-1.5 py-1">lenses</span>
            <span>+</span>
            <span className="rounded border border-border bg-surface px-1.5 py-1">diff</span>
          </div>
        </div>
        <div className="flex justify-center text-muted-foreground" aria-hidden>
          <span className="hidden text-lg md:inline">→</span><span className="text-lg md:hidden">↓</span>
        </div>
        <div className="rounded-lg border border-border bg-surface-2 p-4">
          <div className="flex items-center gap-2 text-foreground">
            <Cloud className="size-4" />
            <span className="font-medium">Live cloud</span>
          </div>
          <p className="mt-2 text-[12px] leading-relaxed text-muted-foreground">Read-only reality. No direct agent access.</p>
        </div>
      </div>
      <div className="relative mt-4 flex items-center gap-2 rounded-lg border border-safe/20 bg-accent/20 px-3.5 py-2.5">
        <ShieldCheck className="size-4 shrink-0" style={{ color: "var(--safe)" }} />
        <span className="text-[12.5px] text-muted-foreground">The agent gets a safe workspace to explore the future; production stays untouched.</span>
      </div>
    </figure>
  );
}
