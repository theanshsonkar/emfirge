import Link from "next/link";
import { Terminal } from "lucide-react";
import { ThemeToggle } from "@/components/theme-toggle";
import { MobileNav } from "@/components/docs/mobile-nav";
import { CommandMenu } from "@/components/docs/command-menu";
import { EmfirgeMark } from "@/components/docs/logo";

export function Topbar() {
  return (
    <header className="sticky top-0 z-50 border-b border-border bg-background/80 backdrop-blur-md supports-[backdrop-filter]:bg-background/65">
      <div className="pointer-events-none absolute inset-0 grid-fade opacity-60" aria-hidden />
      <div className="relative flex h-14 items-center gap-4 px-4 sm:px-6">
        <MobileNav />
        <Link href="/docs" className="flex items-center gap-2">
          <div className="flex size-6 items-center justify-center rounded-md bg-primary text-primary-foreground">
            <EmfirgeMark className="size-4" />
          </div>
          <span className="font-display text-[18px] font-bold tracking-[-0.03em]">emfirge</span>
        </Link>
        <nav className="ml-3 hidden items-center gap-1 text-[13px] md:flex">
          <span className="rounded-md bg-accent px-2.5 py-1 font-medium text-foreground">Docs</span>
          <a href="https://github.com/theanshsonkar/emfirge" className="rounded-md px-2.5 py-1 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground">GitHub</a>
          <a href="https://app.emfirge.cloud" className="rounded-md px-2.5 py-1 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground">Dashboard</a>
        </nav>
        <div className="ml-auto flex items-center gap-2">
          <CommandMenu />
          <a href="/docs/quickstart" className="hidden items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 font-mono text-[12.5px] font-medium transition-colors hover:bg-accent lg:inline-flex">
            <Terminal className="size-3.5" />
            npx @emfirge/mcp
          </a>
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}
