"use client";
import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { RAIL_NAV } from "@/content/site";
import { Mark } from "@/graphics/Mark";
import { Ext } from "./Icons";

function Logo() {
  return (
    <a href="/" className="logo" aria-label="emfirge home">
      <Mark size={28} draw />
      <span>emfirge</span>
    </a>
  );
}

function Nav({ onNav, delay = 0 }: { onNav?: () => void; delay?: number }) {
  const path = (usePathname() || "/").replace(/\/?$/, "/");
  return (
    <nav className="nav" aria-label="Primary">
      {RAIL_NAV.map((n, i) => {
        const active = !n.ext && n.href === path;
        return (
        <a key={n.label} href={n.href} className={`stagger ${active ? "on" : ""}`} style={{ animationDelay: `${delay + 120 + i * 45}ms` }}
          {...(n.ext ? { target: "_blank", rel: "noreferrer" } : {})} onClick={onNav} aria-current={active ? "page" : undefined}>
          {n.label}{n.ext && <> <Ext /></>}
        </a>
        );
      })}
    </nav>
  );
}

function Seg({ agent, set }: { agent: boolean; set: (a: boolean) => void }) {
  return (
    <div className="seg" role="group" aria-label="View">
      <button aria-pressed={!agent} onClick={() => set(false)}>Human</button>
      <button aria-pressed={agent} onClick={() => set(true)}>Agent</button>
    </div>
  );
}

function Otp({ toc, active, onNav, delay = 0 }: { toc: Toc[]; active: string; onNav?: () => void; delay?: number }) {
  return (
    <div className="otp stagger" style={{ animationDelay: `${delay + 480}ms` }}>
      <div className="label" style={{ color: "var(--ink-3)" }}>On this page</div>
      <ul>
        {toc.map((s) => (
          <li key={s.id}><a href={`#${s.id}`} className={active === s.id ? "on" : ""} onClick={onNav}>{s.label}</a></li>
        ))}
      </ul>
    </div>
  );
}

export type Toc = { id: string; label: string };

export function Shell({ children, toc, mdUrl }: { children: React.ReactNode; toc: Toc[]; mdUrl: string }) {
  const [agent, setAgentState] = useState(false);
  const [md, setMd] = useState<string | null>(null);
  const [active, setActive] = useState(toc[0].id);
  const [open, setOpen] = useState(false);

  const setAgent = (a: boolean) => {
    setAgentState(a);
    const u = new URL(window.location.href);
    if (a) u.searchParams.set("agent", "1"); else u.searchParams.delete("agent");
    window.history.replaceState(null, "", u.toString());
    window.scrollTo({ top: 0 });
  };

  useEffect(() => {
    if (new URLSearchParams(window.location.search).get("agent") === "1") setAgentState(true);
  }, []);

  useEffect(() => {
    if (agent && md === null) {
      fetch(mdUrl).then((r) => (r.ok ? r.text() : Promise.reject(r.status))).then(setMd).catch(() => setMd(`Could not load ${mdUrl}`));
    }
  }, [agent, md, mdUrl]);

  // reveal-on-scroll
  useEffect(() => {
    if (agent) return;
    const els = Array.from(document.querySelectorAll<HTMLElement>("[data-reveal]"));
    if (!("IntersectionObserver" in window)) { els.forEach((e) => e.classList.add("in")); return; }
    const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } }), { rootMargin: "0px 0px -8% 0px" });
    els.forEach((e) => io.observe(e));
    return () => io.disconnect();
  }, [agent]);

  // scroll spy
  useEffect(() => {
    if (agent) return;
    const on = () => {
      const line = window.innerHeight * 0.35;
      let cur = toc[0].id;
      for (const s of toc) { const e = document.getElementById(s.id); if (e && e.getBoundingClientRect().top <= line) cur = s.id; }
      setActive(cur);
      (window as unknown as { __spy?: string }).__spy = cur;
      window.dispatchEvent(new CustomEvent("emfirge:spy", { detail: cur }));
    };
    on();
    window.addEventListener("scroll", on, { passive: true });
    window.addEventListener("resize", on);
    return () => { window.removeEventListener("scroll", on); window.removeEventListener("resize", on); };
  }, [agent, toc]);

  return (
    <>
      <aside className="rail" aria-label="Site">
        <div className="rail-in">
          <Logo />
          <Seg agent={agent} set={setAgent} />
          <Nav />
          {!agent && <Otp toc={toc} active={active} />}
        </div>
      </aside>
      <div className="edge" aria-hidden="true" />
      <header className="topbar">
        <Logo />
        <button className="menu-btn" aria-expanded={open} onClick={() => setOpen(!open)}>{open ? "Close" : "Menu"}</button>
      </header>
      {open && (
        <div className="drawer">
          <Seg agent={agent} set={(a) => { setAgent(a); setOpen(false); }} />
          <Nav onNav={() => setOpen(false)} />
          {!agent && <Otp toc={toc} active={active} onNav={() => setOpen(false)} />}
        </div>
      )}
      <main className="main">
        <div className="col">
          {agent ? (
            <>
              <pre className="agent" aria-label={mdUrl}>{md ?? `Loading ${mdUrl} ...`}</pre>
              <p className="cap" style={{ marginBottom: 60 }}>Agent view: this is <a className="uline" href={mdUrl}>{mdUrl}</a>. <a className="uline" href="/llms.txt">All pages (llms.txt)</a></p>
            </>
          ) : children}
        </div>
      </main>
    </>
  );
}
