import Link from "next/link";
import { AlertTriangle, Info, Lightbulb, ArrowLeft, ArrowRight } from "lucide-react";
import { CopyButton } from "./copy-button";

export function slugify(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
}

export function Lead({ children }: { children: React.ReactNode }) {
  return <p className="mt-4 text-[15px] leading-relaxed text-muted-foreground md:text-[16px]">{children}</p>;
}

export function H2({ children }: { children: string }) {
  const id = slugify(children);
  return (
    <h2 id={id} className="group mt-12 mb-1 flex scroll-mt-20 items-center gap-2.5 border-b border-border-soft pb-2.5 font-display text-[18px] font-semibold tracking-tight text-foreground">
      <span className="grid size-3.5 shrink-0 place-items-center text-[var(--tick)]" aria-hidden>
        <svg viewBox="0 0 12 12" className="size-3" fill="none" stroke="currentColor" strokeWidth="1.25">
          <path d="M6 1v10M1 6h10" />
        </svg>
      </span>
      <a href={`#${id}`} className="no-underline">
        {children}
      </a>
      <a href={`#${id}`} aria-label="Link to section" className="font-mono text-[15px] font-normal text-muted-foreground opacity-0 transition-opacity hover:text-foreground group-hover:opacity-100">
        #
      </a>
    </h2>
  );
}

export function H3({ children }: { children: string }) {
  const id = slugify(children);
  return (
    <h3 id={id} className="group mt-8 flex scroll-mt-20 items-center gap-2 font-display text-[15px] font-semibold tracking-tight text-foreground">
      <a href={`#${id}`} className="no-underline">
        {children}
      </a>
      <a href={`#${id}`} aria-label="Link to section" className="font-mono text-[15px] font-normal text-muted-foreground opacity-0 transition-opacity hover:text-foreground group-hover:opacity-100">
        #
      </a>
    </h3>
  );
}

export function P({ children }: { children: React.ReactNode }) {
  return <p className="mt-5 text-[14.5px] leading-[1.75] text-prose">{children}</p>;
}

export function Code({ children }: { children: React.ReactNode }) {
  return <code className="rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[0.85em] text-foreground break-words">{children}</code>;
}

export function Strong({ children }: { children: React.ReactNode }) {
  return <span className="font-medium text-foreground">{children}</span>;
}

/* Inline prose link. Internal hrefs use Next <Link> for client-side nav
   (prefetch + no full reload); external hrefs open in a new tab. */
export function A({ href, children }: { href: string; children: React.ReactNode }) {
  const cls = "text-foreground underline underline-offset-4 transition-opacity hover:opacity-80";
  if (href.startsWith("/")) {
    return <Link href={href} className={cls}>{children}</Link>;
  }
  return (
    <a href={href} target="_blank" rel="noreferrer" className={cls}>
      {children}
    </a>
  );
}

/* Parameter table (Parameter / Type / Required / Description) */
export function ParamList({ children }: { children: React.ReactNode }) {
  return (
    <div className="mt-5 overflow-x-auto rounded-md border border-border">
      <table className="w-full border-collapse text-left text-[13px]">
        <thead>
          <tr className="border-b border-border bg-muted/50 text-[10.5px] uppercase tracking-[0.08em] text-muted-foreground">
            <th className="px-3.5 py-2.5 font-medium">Parameter</th>
            <th className="px-3.5 py-2.5 font-medium">Type</th>
            <th className="px-3.5 py-2.5 font-medium">Required</th>
            <th className="px-3.5 py-2.5 font-medium">Description</th>
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

export function Param({
  name,
  type,
  required,
  children,
}: {
  name: string;
  type: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <tr className="border-b border-border-soft align-top last:border-0">
      <td className="whitespace-nowrap px-3.5 py-3">
        <code className="font-mono text-[13px] font-medium text-foreground">{name}</code>
      </td>
      <td className="whitespace-nowrap px-3.5 py-3 font-mono text-[12px] text-muted-foreground">{type}</td>
      <td className="whitespace-nowrap px-3.5 py-3">
        {required ? (
          <span className="text-[11px] font-medium uppercase tracking-wide text-danger">Yes</span>
        ) : (
          <span className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground/70">No</span>
        )}
      </td>
      <td className="px-3.5 py-3 text-[13.5px] leading-relaxed text-muted-foreground">{children}</td>
    </tr>
  );
}

const CALLOUT = {
  note: { icon: Info, cls: "border-border", bar: "bg-muted-foreground/40", ic: "text-muted-foreground" },
  warning: { icon: AlertTriangle, cls: "border-danger/25", bar: "bg-danger", ic: "text-danger" },
  tip: { icon: Lightbulb, cls: "border-safe/25", bar: "bg-safe", ic: "text-safe" },
};

export function Callout({
  type = "note",
  title,
  children,
}: {
  type?: "note" | "warning" | "tip";
  title?: string;
  children: React.ReactNode;
}) {
  const { icon: Icon, cls, bar, ic } = CALLOUT[type];
  return (
    <div className={`relative my-5 overflow-hidden rounded-lg border ${cls} bg-accent/30 p-4 pl-5`}>
      <span className={`absolute inset-y-0 left-0 w-0.5 ${bar}`} aria-hidden />
      <div className="flex gap-3">
        <Icon className={`mt-0.5 size-4 shrink-0 ${ic}`} />
        <div className="min-w-0 text-[13.5px] leading-relaxed text-muted-foreground">
          {title && <div className="mb-1 font-medium text-foreground">{title}</div>}
          {children}
        </div>
      </div>
    </div>
  );
}

export function Steps({ children }: { children: React.ReactNode }) {
  return <ol className="my-5 space-y-4">{children}</ol>;
}

export function Step({ n, title, children }: { n: number; title: string; children?: React.ReactNode }) {
  return (
    <li className="flex gap-3.5">
      <span className="mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-md bg-accent font-mono text-[12px] font-medium text-foreground">
        {n}
      </span>
      <div className="min-w-0">
        <div className="text-[14.5px] font-medium text-foreground">{title}</div>
        {children && <div className="mt-1 text-[13.5px] leading-relaxed text-muted-foreground">{children}</div>}
      </div>
    </li>
  );
}

export function Badge({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-md border border-border px-2 py-1 text-[12px] text-muted-foreground">
      {children}
    </span>
  );
}

export function CardGrid({ children }: { children: React.ReactNode }) {
  return <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2">{children}</div>;
}

export function Card({ href, title, children }: { href: string; title: string; children: React.ReactNode }) {
  return (
    <Link
      href={href}
      className="lift group rounded-md border border-border bg-surface p-4 hover:border-foreground/25 hover:bg-accent/40"
    >
      <div className="flex items-center justify-between gap-2">
        <div className="font-mono text-[13.5px] font-medium text-foreground">{title}</div>
        <ArrowRight className="size-3.5 shrink-0 text-muted-foreground transition-transform duration-150 group-hover:translate-x-0.5 group-hover:text-foreground" />
      </div>
      <div className="mt-1.5 text-[13px] leading-relaxed text-muted-foreground">{children}</div>
    </Link>
  );
}

export function PrevNext({ prev, next }: { prev?: { title: string; href: string }; next?: { title: string; href: string } }) {
  return (
    <nav className="mt-16 grid grid-cols-2 gap-3 border-t border-border pt-6">
      {prev ? (
        <Link href={prev.href} className="lift group flex min-w-0 flex-col rounded-lg border border-border bg-surface p-4 hover:border-foreground/25">
          <span className="mono-label flex items-center gap-1"><ArrowLeft className="size-3 transition-transform duration-150 group-hover:-translate-x-0.5" /> Previous</span>
          <span className="mt-1 text-[14px] font-medium text-foreground break-words">{prev.title}</span>
        </Link>
      ) : <span />}
      {next ? (
        <Link href={next.href} className="lift group flex min-w-0 flex-col items-end rounded-lg border border-border bg-surface p-4 text-right hover:border-foreground/25">
          <span className="mono-label flex items-center gap-1">Next <ArrowRight className="size-3 transition-transform duration-150 group-hover:translate-x-0.5" /></span>
          <span className="mt-1 text-[14px] font-medium text-foreground break-words">{next.title}</span>
        </Link>
      ) : <span />}
    </nav>
  );
}

/* Endpoint-style tool bar, badge + signature + copy (API-reference feel) */
export function ToolSignature({ name, args, returns }: { name: string; args: string; returns: string }) {
  return (
    <div className="mt-5 flex items-center gap-3 rounded-md border border-border bg-surface px-3 py-2.5">
      <span className="shrink-0 rounded bg-primary px-2 py-1 font-mono text-[11px] font-semibold uppercase tracking-wide text-primary-foreground">
        Tool
      </span>
      <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap font-mono text-[12.5px] leading-relaxed rail-scroll">
        <span className="font-medium text-foreground">{name}</span>
        <span className="text-muted-foreground">({args})</span>
        <span className="mx-2" style={{ color: "var(--safe)" }}>→</span>
        <span className="text-muted-foreground">{returns}</span>
      </code>
      <CopyButton text={`${name}(${args})`} label="Copy tool signature" />
    </div>
  );
}

/* Severity / status legend using the functional color tokens */
export function SeverityLegend() {
  const items = [
    { c: "var(--danger)", label: "Critical" },
    { c: "var(--muted-foreground)", label: "Moderate" },
    { c: "color-mix(in oklch, var(--muted-foreground) 55%, transparent)", label: "Low" },
    { c: "var(--safe)", label: "Safe / proven" },
  ];
  return (
    <div className="my-5 flex flex-wrap items-center gap-x-5 gap-y-2 rounded-lg border border-border bg-surface px-4 py-3 text-[12.5px] text-muted-foreground">
      <span className="mono-label">severity</span>
      {items.map((it) => (
        <span key={it.label} className="flex items-center gap-1.5">
          <span className="size-2 rounded-full" style={{ background: it.c }} />
          {it.label}
        </span>
      ))}
    </div>
  );
}

/* Page header used at the top of every doc page. The `eyebrow` prop is kept
   for API compatibility but no longer rendered, the breadcrumb already
   carries the section, so showing it again here just stutters. */
export function DocHeader({ eyebrow: _eyebrow, title, mono, children }: { eyebrow?: string; title: string; mono?: boolean; children?: React.ReactNode }) {
  return (
    <header className="relative isolate mb-2">
      {/* header-grid intentionally omitted: it doubled up with the topbar's
          full-bleed .grid-fade in the strip under the topbar, at a different
          cell size/origin, which read as a broken grid. Topbar grid remains. */}
      <h1
        className={`text-pretty text-[2rem] font-semibold leading-[1.08] tracking-[-0.02em] md:text-[2.6rem] ${
          mono ? "font-mono tracking-[-0.01em]" : "font-display"
        }`}
      >
        {title}
      </h1>
      {children}
    </header>
  );
}
