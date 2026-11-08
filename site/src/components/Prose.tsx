"use client";
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { NOTES } from "@/content/site";

function Fn({ text, children, block }: { text: string; children: React.ReactNode; block?: boolean }) {
  const [open, setOpen] = useState(false);
  const [dx, setDx] = useState(0);
  const ref = useRef<HTMLSpanElement>(null);
  const pop = useRef<HTMLSpanElement>(null);
  const dxRef = useRef(0);
  const btnRef = useRef<HTMLButtonElement>(null);
  const [phoneTop, setPhoneTop] = useState<number | null>(null);
  // Close on an outside tap or click, and on Escape.
  useEffect(() => {
    if (!open) return;
    const off = (e: Event) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("pointerdown", off); document.addEventListener("keydown", esc);
    return () => { document.removeEventListener("pointerdown", off); document.removeEventListener("keydown", esc); };
  }, [open]);
  // Wide screens: keep the popover 16px inside the viewport. Phones: it spans its paragraph (16px+ gutters), just under the line of the note mark.
  useLayoutEffect(() => {
    const p = pop.current, btn = btnRef.current;
    if (!open || !p || !btn) return;
    const fit = () => {
      if (window.matchMedia("(max-width: 700px)").matches) {
        const para = btn.closest("p") as HTMLElement | null;
        if (para) setPhoneTop(btn.getBoundingClientRect().bottom - para.getBoundingClientRect().top + 4);
        dxRef.current = 0; setDx(0);
        return;
      }
      setPhoneTop(null);
      const r = p.getBoundingClientRect(), vw = document.documentElement.clientWidth;
      const left = r.left - dxRef.current, right = r.right - dxRef.current;
      const next = right > vw - 16 ? vw - 16 - right : left < 16 ? 16 - left : 0;
      dxRef.current = next; setDx(next);
    };
    fit();
    window.addEventListener("resize", fit);
    return () => window.removeEventListener("resize", fit);
  }, [open]);
  return (
    <span className="pw" ref={ref} style={block ? { display: "inline-block" } : undefined}>
      <span className="lk">{children}</span>
      <button className="fn" ref={btnRef} aria-expanded={open} aria-label="Note" onClick={() => setOpen(!open)}><i /></button>
      {open && <span className="pop" role="note" ref={pop} style={phoneTop !== null ? { top: phoneTop } : { transform: `translateX(${dx}px)` }}>{text}</span>}
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
