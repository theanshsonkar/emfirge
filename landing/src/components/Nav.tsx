import { NAV } from "@/content";
import { Button } from "./Button";
import { Logo } from "./Logo";
import { Frame } from "./Frame";

export function Nav() {
  return (
    <header className="sticky top-0 z-40 border-b border-line bg-white">
      <Frame>
        <nav aria-label="Primary" className="flex h-16 items-center justify-between gap-4 px-4 sm:px-6">
          <div className="flex items-center gap-8">
            <a href="#top" aria-label={NAV.home} className="text-ink">
              <Logo />
            </a>
            <ul className="hidden items-center gap-6 md:flex">
              {NAV.items.map((i) => (
                <li key={i.label}>
                  <a href={i.href} className="text-sm font-medium text-ink-2 hover:text-ink">
                    {i.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>
          <div className="flex items-center gap-2">
            <Button href={NAV.signIn.href} variant="outline">
              {NAV.signIn.label}
            </Button>
            <Button href={NAV.start.href}>{NAV.start.label}</Button>
          </div>
        </nav>
      </Frame>
    </header>
  );
}
