"use client";
import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { RAIL_GROUPS } from "@/content/site";
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
  let i = 0;
  return (
    <nav className="nav" aria-label="Primary">
      {RAIL_GROUPS.map((g) => (
        <div className="nav-g" key={g.label} role="group" aria-label={g.label}>
          <div className="label nav-gl stagger" style={{ animationDelay: `${delay + 120 + i * 45}ms` }}>{g.label}</div>
          {g.items.map((n) => {
            const active = !n.ext && n.href === path;
            const k = i++;
            return (
              <a key={n.label} href={n.href} className={`stagger ${active ? "on" : ""}`} style={{ animationDelay: `${delay + 120 + (k + 1) * 45}ms` }}
                {...(n.ext ? { target: "_blank", rel: "noreferrer" } : {})} onClick={onNav} aria-current={active ? "page" : undefined}>
                {n.label}{n.ext && <> <Ext /></>}
              </a>
            );
          })}
        </div>
      ))}
    </nav>
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
  const [active, setActive] = useState(toc[0].id);
  const [open, setOpen] = useState(false);

  // old shared links: ?agent=1 goes straight to this page's .md
  useEffect(() => {
    if (new URLSearchParams(window.location.search).get("agent") === "1") window.location.replace(mdUrl);
  }, [mdUrl]);

  // reveal-on-scroll
  useEffect(() => {
    const els = Array.from(document.querySelectorAll<HTMLElement>("[data-reveal]"));
    if (!("IntersectionObserver" in window)) { els.forEach((e) => e.classList.add("in")); return; }
    const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } }), { rootMargin: "0px 0px -8% 0px" });
    els.forEach((e) => io.observe(e));
    return () => io.disconnect();
  }, []);

  // scroll spy
  useEffect(() => {
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
  }, [toc]);

  return (
    <>
      <aside className="rail" aria-label="Site">
        <div className="rail-in">
          <Logo />
          <Nav />
          <Otp toc={toc} active={active} />
        </div>
      </aside>
      <div className="edge" aria-hidden="true" />
      <header className="topbar">
        <Logo />
        <button className="menu-btn" aria-expanded={open} onClick={() => setOpen(!open)}>{open ? "Close" : "Menu"}</button>
      </header>
      {open && (
        <div className="drawer">
          <Nav onNav={() => setOpen(false)} />
          <Otp toc={toc} active={active} onNav={() => setOpen(false)} />
        </div>
      )}
      <main className="main">
        <div className="col">
          {children}
        </div>
      </main>
    </>
  );
}
