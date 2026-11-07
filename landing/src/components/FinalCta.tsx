import { Logo } from "./Logo";
import { Container } from "./ui/Container";
import { Section } from "./ui/Section";
import { CommandBox } from "./ui/CommandBox";
import { ButtonLink } from "./ui/Button";
import { CONNECT_CMD, FOOTER_LINKS } from "@/content";

export function FinalCta() {
  return (
    <>
      <Section aria-label="Get started" className="border-t border-line">
        <div className="flex flex-col items-center text-center">
          <h2 className="max-w-[16ch] font-display text-[clamp(44px,7vw,88px)] leading-[1] tracking-[-0.02em] text-balance">
            Let your agents own the cloud. <em className="text-forge">Safely.</em>
          </h2>
          <div className="mt-10 flex w-full max-w-[520px] flex-col gap-4 sm:flex-row sm:items-center sm:justify-center sm:max-w-none">
            <CommandBox command={CONNECT_CMD} className="sm:w-auto sm:min-w-[400px]" />
            <ButtonLink href="#get-started">Get started</ButtonLink>
          </div>
        </div>
      </Section>
      <footer className="border-t border-line py-12">
        <Container className="flex flex-col gap-8 md:flex-row md:items-start md:justify-between">
          <div>
            <Logo />
            <p className="mt-3 text-sm text-muted">The harness for cloud agents.</p>
          </div>
          <nav aria-label="Footer">
            <ul className="flex flex-wrap gap-x-6 gap-y-3 text-sm text-muted">
              {FOOTER_LINKS.map((l) => (
                <li key={l.label}><a href={l.href} className="hover:text-paper">{l.label}</a></li>
              ))}
            </ul>
          </nav>
        </Container>
        <Container className="mt-8 text-sm text-muted">Built by Ansh Sonkar</Container>
      </footer>
    </>
  );
}
