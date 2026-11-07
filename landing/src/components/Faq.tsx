"use client";

import { useReduced } from "@/lib/useReduced";
import { useState } from "react";
import { motion } from "motion/react";
import { Plus } from "lucide-react";
import { Section, Eyebrow, H2 } from "./ui/Section";
import { cn } from "@/lib/cn";
import { FAQ } from "@/content";

/** A native <details>, with its open/close animated. Works without JS. */
function FaqItem({ q, a }: { q: string; a: string }) {
  const reduce = useReduced();
  const [attr, setAttr] = useState(false); // the <details open> attribute
  const [open, setOpen] = useState(false); // logical state, drives the animation

  return (
    <details open={attr} className="border-b border-white/10">
      <summary
        onClick={(e) => {
          e.preventDefault();
          if (open) {
            setOpen(false);
          } else {
            setAttr(true);
            setOpen(true);
          }
        }}
        className="flex cursor-pointer items-center justify-between gap-6 py-5 text-lg font-medium"
      >
        {q}
        <Plus size={20} aria-hidden="true" className={cn("shrink-0 text-forge transition-transform", open && "rotate-45")} />
      </summary>
      <motion.div
        data-faq-body
        initial={false}
        animate={{ height: open ? "auto" : 0, opacity: open ? 1 : 0 }}
        transition={{ duration: reduce ? 0 : 0.25, ease: "easeOut" }}
        onAnimationComplete={() => { if (!open) setAttr(false); }}
        className="overflow-hidden"
      >
        <p className="max-w-[62ch] pb-6 leading-relaxed text-muted">{a}</p>
      </motion.div>
    </details>
  );
}

export function Faq() {
  return (
    <Section aria-labelledby="faq-h" className="py-12 md:py-16">
      <div className="mx-auto max-w-[760px]">
        <Eyebrow>FAQ</Eyebrow>
        <H2 id="faq-h">Questions.</H2>
        <div className="mt-8 border-t border-white/10">
          {FAQ.map((f) => (
            <FaqItem key={f.q} {...f} />
          ))}
        </div>
      </div>
    </Section>
  );
}
