"use client";
import { useEffect, useRef, useState } from "react";
import { NOTES } from "@/content/site";

function Fn({ text, children, block }: { text: string; children: React.ReactNode; block?: boolean }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    if (!open) return;
    const off = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", off); document.addEventListener("keydown", esc);
    return () => { document.removeEventListener("mousedown", off); document.removeEventListener("keydown", esc); };
  }, [open]);
  return (
    <span className="pw" ref={ref} style={block ? { display: "inline-block" } : undefined}>
      <span className="lk">{children}</span>
      <button className="fn" aria-expanded={open} aria-label="Note" onClick={() => setOpen(!open)}>+</button>
      {open && <span className="pop" role="note">{text}</span>}
    </span>
  );
}

export function Prose() {
  return (
    <section id="mission" className="prose" data-reveal>
      <p>
        The path to agents that run infrastructure isn&apos;t a smarter model. It&apos;s a{" "}
        <Fn text={NOTES.world}>true world for them to work in</Fn>: what exists, what&apos;s live, what depends on what,
        and a safe copy to try a change on before it&apos;s real.
      </p>
      <p><Fn text={NOTES.trust}>Intelligence is no longer the constraint. Trust is.</Fn></p>
      <p>
        Agents can already write the Terraform and run the CLI. What they can&apos;t do is see what a change will break,
        and owners can&apos;t let them near production without that.
      </p>
      <p>
        We built the hard parts: a branch engine for your live AWS, <b>six checks</b> that say what a change does to your
        data, exposure, money, availability, control and the outside world, and a <b>record</b> of what was applied,
        bound by hash to the verdict it was judged with.
      </p>
      <p>
        <b>Emfirge supplies the truth. Your agent supplies the intelligence.</b> Emfirge has no AI inside: the same branch
        always gets the same answer, and it never writes to your cloud.
      </p>
    </section>
  );
}
