"use client";

import { useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { Menu, X } from "lucide-react";
import { Logo, GithubIcon } from "./Logo";
import { ButtonLink } from "./ui/Button";
import { Frame } from "./ui/Frame";
import { LINKS, NAV_ITEMS } from "@/content";

export function Nav() {
  const [open, setOpen] = useState(false);
  const close = () => setOpen(false);

  return (
    <header className="fixed inset-x-0 top-4 z-50 px-4">
      <div className="mx-auto max-w-[880px]">
        <Frame radius={28} innerClassName="bg-[#0b0b0c]/70 backdrop-blur-xl">
          <div className="flex h-14 items-center justify-between gap-4 pl-5 pr-2">
            <a href="#top" aria-label="Emfirge home" onClick={close}>
              <Logo />
            </a>
            <nav aria-label="Main" className="hidden items-center gap-7 md:flex">
              {NAV_ITEMS.map((i) => (
                <a key={i.label} href={i.href} className="text-sm text-muted transition-colors hover:text-paper">
                  {i.label}
                </a>
              ))}
              <a href={LINKS.github} aria-label="Emfirge on GitHub" className="text-muted transition-colors hover:text-paper">
                <GithubIcon size={19} />
              </a>
              <ButtonLink href="#get-started" className="h-10 rounded-full px-5 text-sm">
                Get started
              </ButtonLink>
            </nav>
            <div className="flex items-center gap-2 md:hidden">
              <ButtonLink href="#get-started" className="h-10 rounded-full px-4 text-sm" onClick={close}>
                Get started
              </ButtonLink>
              <button
                type="button"
                aria-expanded={open}
                aria-controls="mobile-menu"
                aria-label={open ? "Close menu" : "Open menu"}
                onClick={() => setOpen((o) => !o)}
                className="inline-flex size-10 items-center justify-center rounded-full text-paper hover:bg-white/10"
              >
                {open ? <X size={20} /> : <Menu size={20} />}
              </button>
            </div>
          </div>
        </Frame>
        <AnimatePresence>
          {open && (
            <motion.nav
              id="mobile-menu"
              aria-label="Mobile"
              initial={{ opacity: 0, y: -8, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -8, scale: 0.98 }}
              transition={{ duration: 0.18 }}
              className="mt-2 md:hidden"
            >
              <Frame radius={20} innerClassName="bg-[#0b0b0c]/90 backdrop-blur-xl">
                <ul className="flex flex-col px-5 py-2">
                  {NAV_ITEMS.map((i) => (
                    <li key={i.label}>
                      <a href={i.href} onClick={close} className="block py-3 text-base text-paper">
                        {i.label}
                      </a>
                    </li>
                  ))}
                  <li>
                    <a href={LINKS.github} onClick={close} className="flex items-center gap-2 py-3 text-base text-paper">
                      <GithubIcon size={18} /> GitHub
                    </a>
                  </li>
                </ul>
              </Frame>
            </motion.nav>
          )}
        </AnimatePresence>
      </div>
    </header>
  );
}
