import { FOOTER } from "@/content";
import { Frame } from "./Frame";
import { Logo } from "./Logo";

export function Footer() {
  return (
    <footer>
      <Frame>
        <div className="grid gap-10 px-4 py-14 sm:px-8 lg:grid-cols-[1.2fr_2.8fr] lg:px-12">
          <div className="text-ink">
            <Logo />
            <p className="mt-3 text-sm text-ink-3">{FOOTER.tagline}</p>
          </div>
          <div className="grid grid-cols-2 gap-8 sm:grid-cols-4">
            {FOOTER.columns.map((c) => (
              <nav key={c.title} aria-label={c.title}>
                <h2 className="text-sm font-medium text-ink">{c.title}</h2>
                <ul className="mt-3 space-y-2">
                  {c.links.map((l) => (
                    <li key={l.label}>
                      <a href={l.href} className="break-words text-sm text-ink-2 hover:text-ink hover:underline">
                        {l.label}
                      </a>
                    </li>
                  ))}
                </ul>
              </nav>
            ))}
          </div>
        </div>
        <div className="border-t border-line px-4 py-5 text-sm text-ink-3 sm:px-8 lg:px-12">{FOOTER.legal}</div>
      </Frame>
    </footer>
  );
}
