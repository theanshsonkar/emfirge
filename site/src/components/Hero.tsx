"use client";
import { useEffect, useRef, useState } from "react";
import { HERO, LINKS, SETUP_PROMPT } from "@/content/site";
import { Mark } from "@/graphics/Mark";
import { Delta, HERO_DELTA } from "@/graphics/Delta";
import { Caret, Check, Copy, Ext } from "./Icons";

// Copies the setup prompt. Shared by the hero button and the copy bar.
function useCopyPrompt() {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(SETUP_PROMPT); } catch {
      const t = document.createElement("textarea"); t.value = SETUP_PROMPT; document.body.appendChild(t); t.select();
      try { document.execCommand("copy"); } catch {} t.remove();
    }
    setDone(true); setTimeout(() => setDone(false), 1800);
  };
  return { done, copy };
}

export function CopyBar() {
  const [open, setOpen] = useState(false);
  const { done, copy } = useCopyPrompt();
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const off = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", off); document.addEventListener("keydown", esc);
    return () => { document.removeEventListener("mousedown", off); document.removeEventListener("keydown", esc); };
  }, []);
  const enc = encodeURIComponent(SETUP_PROMPT);
  return (
    <div className="copybar" ref={ref}>
      <button className="main-b" onClick={copy} aria-live="polite">{done ? "Copied" : HERO.copy}</button>
      <span className="ico" aria-hidden="true">{done ? <Check /> : <Copy />}</span>
      <button className="car" aria-label="More ways to open the setup prompt" aria-expanded={open} onClick={() => setOpen(!open)}><Caret /></button>
      {open && (
        <div className="menu" role="menu">
          <a role="menuitem" href={`https://claude.ai/new?q=${enc}`} target="_blank" rel="noreferrer">Open in Claude</a>
          <a role="menuitem" href={`https://chatgpt.com/?q=${enc}`} target="_blank" rel="noreferrer">Open in ChatGPT</a>
          <a role="menuitem" href={`cursor://anysphere.cursor-deeplink/prompt?text=${enc}`}>Open in Cursor</a>
        </div>
      )}
    </div>
  );
}

export function Hero() {
  const { done, copy } = useCopyPrompt();
  return (
    <section>
      <div className="pill stagger" style={{ animationDelay: "60ms" }}>
        <span><i className="dot" />{HERO.pill}</span>
        <a href={LINKS.cli}>{HERO.pillLink} <Ext size={9} /></a>
      </div>
      <h1 className="h1">{HERO.h1}</h1>
      <p className="sub">{HERO.sub}</p>
      <div className="btns">
        <button className="btn btn-p" onClick={copy} aria-live="polite" data-copy-primary><span className="tile"><Mark size={24} trunk="#0A7A4B" branch="#0A7A4B" /></span>{done ? HERO.primaryDone : HERO.primary}</button>
        <a className="btn btn-s" href={LINKS.quickstart}>{HERO.secondary} <Ext size={11} /></a>
      </div>
      <CopyBar />
      <div className="works">
        <span className="label">Works with</span>
        {HERO.worksWith.map((w) => <a key={w} href={w === "MCP" ? `${LINKS.cli}#mcp-adapter` : LINKS.cli}>{w}</a>)}
      </div>
      <div className="media" aria-hidden="true"><Delta opts={HERO_DELTA} /></div>
    </section>
  );
}
