import Link from "next/link";
import { ArrowRight } from "lucide-react";
import { EmfirgeMark } from "@/components/docs/logo";

export default function NotFound() {
  return (
    <main className="grid min-h-screen place-items-center bg-background px-6">
      <div className="grid-fade pointer-events-none absolute inset-0 opacity-50" aria-hidden />
      <div className="relative max-w-md text-center">
        <div className="mx-auto mb-6 flex size-11 items-center justify-center rounded-xl bg-primary text-primary-foreground">
          <EmfirgeMark className="size-6" />
        </div>
        <div className="tag">Error 404</div>
        <h1 className="mt-3 font-display text-3xl font-semibold tracking-tight">This page took a branch that doesn&apos;t exist.</h1>
        <p className="mt-3 text-[14.5px] leading-relaxed text-muted-foreground">
          The page you&apos;re looking for isn&apos;t here. Head back to the docs, or press{" "}
          <kbd className="rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[11px]">⌘K</kbd>{" "}
          to search.
        </p>
        <div className="mt-7 flex items-center justify-center gap-3">
          <Link
            href="/docs"
            className="inline-flex items-center gap-1.5 rounded-lg bg-primary px-4 py-2 text-[13.5px] font-medium text-primary-foreground transition-opacity hover:opacity-90"
          >
            Back to docs <ArrowRight className="size-3.5" />
          </Link>
          <Link
            href="/docs/quickstart"
            className="inline-flex items-center gap-1.5 rounded-lg border border-border px-4 py-2 text-[13.5px] font-medium transition-colors hover:bg-accent"
          >
            Quickstart
          </Link>
        </div>
      </div>
    </main>
  );
}
