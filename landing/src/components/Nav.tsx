"use client";

import { useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { Menu, X } from "lucide-react";
import { Logo, GithubIcon } from "./Logo";
import { Container } from "./ui/Container";
import { ButtonLink } from "./ui/Button";
import { LINKS, NAV_ITEMS } from "@/content";

export function Nav() {
  const [open, setOpen] = useState(false);
  const close = () => setOpen(false);

  return (
    <header className="sticky top-0 z-50 border-b border-line bg-ink/80 backdrop-blur-md">
      <Container className="flex h-16 items-center justify-between gap-4">
        <a href="#top" aria-label="Emfirge home" onClick={close}>
          <Logo />
        </a>
        <nav aria-label="Main" className="hidden items-center gap-8 md:flex">
          {NAV_ITEMS.map((i) => (
            <a key={i.label} href={i.href} className="text-sm text-muted hover:text-paper">{i.label}</a>
          ))}
          <a href={LINKS.github} aria-label="Emfirge on GitHub" className="text-muted hover:text-paper">
            <GithubIcon />
          </a>
          <ButtonLink href="#get-started" className="h-10">Get started</ButtonLink>
        </nav>
        <div className="flex items-center gap-2 md:hidden">
          <ButtonLink href="#get-started" className="h-10 px-4" onClick={close}>Get started</ButtonLink>
          <button
            type="button"
            aria-expanded={open}
            aria-controls="mobile-menu"
            aria-label={open ? "Close menu" : "Open menu"}
            onClick={() => setOpen((o) => !o)}
            className="inline-flex size-10 items-center justify-center rounded-lg border border-line text-paper"
          >
            {open ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
      </Container>
      <AnimatePresence>
        {open && (
          <motion.nav
            id="mobile-menu"
            aria-label="Mobile"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden border-t border-line bg-ink md:hidden"
          >
            <Container>
              <ul className="flex flex-col py-2">
                {NAV_ITEMS.map((i) => (
                  <li key={i.label}>
                    <a href={i.href} onClick={close} className="block py-3 text-base text-paper">{i.label}</a>
                  </li>
                ))}
                <li>
                  <a href={LINKS.github} onClick={close} className="flex items-center gap-2 py-3 text-base text-paper">
                    <GithubIcon size={18} /> GitHub
                  </a>
                </li>
              </ul>
            </Container>
          </motion.nav>
        )}
      </AnimatePresence>
    </header>
  );
}
