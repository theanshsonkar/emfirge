"use client";
import { Fragment, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { usePathname } from "next/navigation";
import { RAIL_GROUPS } from "@/content/site";
import { Mark } from "@/graphics/Mark";
import { BgDelta } from "@/graphics/BgDelta";
import { Ext } from "./Icons";

function Logo() {
  return (
    <a href="/" className="logo" aria-label="emfirge home">
      <Mark size={28} draw />
      <span>emfirge</span>
    </a>
  );
}

// With `toc` (the desktop rail) the page's sections nest under its own link as an "On this page" list;
// without it (the mobile drawer) the nav is the flat list and Otp follows it.
function Nav({ onNav, delay = 0, toc, active }: { onNav?: () => void; delay?: number; toc?: Toc[]; active?: string }) {
  const path = (usePathname() || "/").replace(/\/?$/, "/");
  let i = 0;
  return (
    <nav className="nav" aria-label="Primary">
      {RAIL_GROUPS.map((g) => (
        <div className="nav-g" key={g.label} role="group" aria-label={g.label}>
          <div className="label nav-gl stagger" style={{ animationDelay: `${delay + 120 + i * 45}ms` }}>{g.label}</div>
          {g.items.map((n) => {
            const here = !n.ext && n.href === path;
            const k = i++;
            return (
              <Fragment key={n.label}>
                <a href={n.href} className={`stagger ${here ? "on" : ""}`} style={{ animationDelay: `${delay + 120 + (k + 1) * 45}ms` }}
                  {...(n.ext ? { target: "_blank", rel: "noreferrer" } : {})} onClick={onNav} aria-current={here ? "page" : undefined}>
                  {n.label}{n.ext && <> <Ext /></>}
                </a>
                {here && toc && (
                  <ul className="tb stagger" aria-label="On this page" style={{ animationDelay: `${delay + 480}ms` }}>
                    {toc.map((t) => (
                      <li key={t.id}><a href={`#${t.id}`} className={active === t.id ? "on" : ""}>{t.label}</a></li>
                    ))}
                  </ul>
                )}
              </Fragment>
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

type Geo = { w: number; h: number; top: number; links: { y: number; on: boolean }[]; secs: number[] };

const TRUNK = 4, BRANCH = 22; // x of the trunk and of the section branch, inside .rail-in
const GREEN = "#0a7a4b", GREY = "rgba(11,16,21,.22)", NODE = "rgba(11,16,21,.45)";

// The branch-tree lines: an aria-hidden SVG over the rail nav. Geometry is measured from the rendered links, so it
// follows wrapping, fonts and window size; which section is current comes from the scroll spy (`active`).
// Rects are read (not offsetTop) so fractional line heights stay exact; animationend re-measures after the stagger transforms settle.
function RailInner({ toc, active }: { toc: Toc[]; active: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const [geo, setGeo] = useState<Geo | null>(null);

  const measure = useCallback(() => {
    const rin = ref.current;
    const logo = rin?.querySelector(".logo svg");
    if (!rin || !logo || rin.offsetParent === null) return; // rail hidden (< 1024px): nothing to draw
    const R = rin.getBoundingClientRect();
    const cy = (el: Element) => { const r = el.getBoundingClientRect(); return r.top - R.top + r.height / 2; };
    const next: Geo = {
      w: R.width,
      h: rin.scrollHeight,
      top: logo.getBoundingClientRect().bottom - R.top + 10,
      links: Array.from(rin.querySelectorAll(".nav-g > a")).map((a) => ({ y: cy(a), on: a.getAttribute("aria-current") === "page" })),
      secs: Array.from(rin.querySelectorAll(".tb a")).map(cy),
    };
    setGeo((g) => (g && JSON.stringify(g) === JSON.stringify(next) ? g : next));
  }, []);

  useLayoutEffect(() => {
    measure();
    const rin = ref.current;
    if (!rin) return;
    const ro = new ResizeObserver(measure);
    ro.observe(rin);
    window.addEventListener("resize", measure);
    document.fonts?.ready.then(measure);
    return () => { ro.disconnect(); window.removeEventListener("resize", measure); };
  }, [measure]);

  return (
    <div className="rail-in" ref={ref} onAnimationEnd={measure}>
      <Logo />
      <Nav toc={toc} active={active} />
      {geo && <TreeSvg geo={geo} cur={Math.max(0, toc.findIndex((t) => t.id === active))} />}
    </div>
  );
}

function TreeSvg({ geo, cur }: { geo: Geo; cur: number }) {
  const { links, secs } = geo;
  if (!links.length) return null;
  const X = TRUNK, BX = BRANCH;
  const act = links.find((l) => l.on);
  const lastSec = secs[secs.length - 1];
  // the branch rejoins the trunk a little below its last section; the trunk runs at least that far
  const merge = act && secs.length ? lastSec + 22 : 0;
  const end = Math.max(links[links.length - 1].y, merge);
  return (
    <svg className="rail-tree" aria-hidden="true" width={geo.w} height={geo.h} focusable="false">
      <path d={`M${X} ${geo.top}V${end}`} stroke={GREY} strokeWidth={1} fill="none" />
      {links.map((l, i) => l.on ? (
        <g key={i}>
          <rect x={X - 3.5} y={l.y - 3.5} width={7} height={7} fill={GREEN} />
          <path d={`M${X + 4} ${l.y}H18`} stroke={GREEN} strokeWidth={1} />
        </g>
      ) : (
        <g key={i}>
          <rect x={X - 2.5} y={l.y - 2.5} width={5} height={5} fill="#fff" stroke={NODE} strokeWidth={1} />
          <path d={`M${X + 4} ${l.y}H14`} stroke={GREY} strokeWidth={1} />
        </g>
      ))}
      {act && secs.length > 0 && (() => {
        const ay = act.y, ci = Math.min(cur, secs.length - 1);
        return (
          <g>
            <path d={`M${X} ${ay}C${X} ${ay + 12},${BX} ${ay + 6},${BX} ${ay + 20}V${secs[ci]}`} stroke={GREEN} strokeWidth={1.5} fill="none" />
            <path d={`M${BX} ${secs[ci]}V${lastSec}C${BX} ${lastSec + 14},${X} ${lastSec + 8},${X} ${merge}`} stroke={GREY} strokeWidth={1} fill="none" strokeDasharray="2 3" />
            {secs.map((y, k) => (
              <g key={k}>
                {k < ci ? <rect x={BX - 2} y={y - 2} width={4} height={4} fill={GREEN} />
                  : k === ci ? <>
                    <rect x={BX - 3.5} y={y - 3.5} width={7} height={7} fill="#fff" stroke={GREEN} strokeWidth={1.5} />
                    <rect x={BX - 1} y={y - 1} width={2} height={2} fill={GREEN} />
                  </>
                  : <rect x={BX - 2} y={y - 2} width={4} height={4} fill="#fff" stroke="rgba(11,16,21,.4)" strokeWidth={1} />}
                <path d={`M${BX + (k === ci ? 5 : 3)} ${y}H34`} stroke={k <= ci ? GREEN : GREY} strokeWidth={1} />
              </g>
            ))}
          </g>
        );
      })()}
    </svg>
  );
}

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
    // measured at most once per frame, and only announced when the section changes (Safari fires scroll often)
    let raf = 0, prev = "";
    const measure = () => {
      raf = 0;
      const line = window.innerHeight * 0.35;
      let cur = toc[0].id;
      for (const s of toc) { const e = document.getElementById(s.id); if (e && e.getBoundingClientRect().top <= line) cur = s.id; }
      if (cur === prev) return;
      prev = cur;
      setActive(cur);
      (window as unknown as { __spy?: string }).__spy = cur;
      window.dispatchEvent(new CustomEvent("emfirge:spy", { detail: cur }));
    };
    const on = () => { if (!raf) raf = requestAnimationFrame(measure); };
    measure();
    window.addEventListener("scroll", on, { passive: true });
    window.addEventListener("resize", on);
    return () => { if (raf) cancelAnimationFrame(raf); window.removeEventListener("scroll", on); window.removeEventListener("resize", on); };
  }, [toc]);

  return (
    <>
      <BgDelta />
      <aside className="rail" aria-label="Site">
        <RailInner toc={toc} active={active} />
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
