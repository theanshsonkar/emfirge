import { NAV } from "@/content";
import { TestMark } from "./TestMark";

export function Header() {
  return (
    <header className="mx-auto flex max-w-[1440px] items-center justify-between px-4 py-4 sm:px-8">
      <a href="#top" className="flex items-center gap-2.5" aria-label="Emfirge, home">
        <TestMark size={28} />
        <span className="text-[21px] font-bold tracking-[-0.01em]">emfirge</span>
      </a>
      <nav aria-label="Main" className="label flex items-center gap-4 sm:gap-7">
        {NAV.links.map((l) => (
          <a
            key={l.label}
            href={l.href}
            className={`rounded-sm underline-offset-4 hover:underline ${l.hideOnMobile ? "hidden sm:inline" : ""}`}
          >
            {l.label}
          </a>
        ))}
      </nav>
    </header>
  );
}
