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

// The primary nav, shared by the desktop rail and the phone drawer. The current page's sections nest under its own link
// as an "On this page" list (the branch of the tree). `stagger` is the rail's entrance animation; the drawer skips it.
function Nav({ onNav, delay = 0, toc, active, stagger = true }: { onNav?: () => void; delay?: number; toc?: Toc[]; active?: string; stagger?: boolean }) {
  const path = (usePathname() || "/").replace(/\/?$/, "/");
  let i = 0;
  const st = stagger ? "stagger " : "";
  return (
    <nav className="nav" aria-label="Primary">
      {RAIL_GROUPS.map((g) => (
        <div className="nav-g" key={g.label} role="group" aria-label={g.label}>
          <div className={`label nav-gl${stagger ? " stagger" : ""}`} style={stagger ? { animationDelay: `${delay + 120 + i * 45}ms` } : undefined}>{g.label}</div>
          {g.items.map((n) => {
            const here = !n.ext && n.href === path;
            const k = i++;
            return (
              <Fragment key={n.label}>
                <a href={n.href} className={`${st}${here ? "on" : ""}`} style={stagger ? { animationDelay: `${delay + 120 + (k + 1) * 45}ms` } : undefined}
                  {...(n.ext ? { target: "_blank", rel: "noreferrer" } : {})} onClick={onNav} aria-current={here ? "page" : undefined}>
                  {n.label}{n.ext && <> <Ext /></>}
                </a>
                {here && toc && (
                  <ul className={`tb${stagger ? " stagger" : ""}`} aria-label="On this page" style={stagger ? { animationDelay: `${delay + 480}ms` } : undefined}>
                    {toc.map((t) => (
                      <li key={t.id}><a href={`#${t.id}`} className={active === t.id ? "on" : ""} onClick={onNav}>{t.label}</a></li>
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

export type Toc = { id: string; label: string };

type Geo = { w: number; h: number; top: number; links: { y: number; on: boolean }[]; secs: number[] };

// Sizes of one tree (x of the trunk and of the section branch, where the ticks end, and the fork / merge curves), so the
// desktop rail, the phone drawer and the section sheet all draw with the same code. All x are inside the measured root.
type TreeCfg = { X: number; BX: number; tick: number; tickOn: number; secEnd: number; fork: [number, number, number]; join: [number, number, number]; lead: number };
const RAIL: TreeCfg = { X: 4, BX: 22, tick: 14, tickOn: 18, secEnd: 34, fork: [12, 6, 20], join: [14, 8, 22], lead: 0 };
const DRAWER: TreeCfg = { X: 6, BX: 26, tick: 16, tickOn: 20, secEnd: 38, fork: [14, 8, 24], join: [16, 10, 26], lead: 0 };
const SHEET: TreeCfg = { X: 0, BX: 6, tick: 0, tickOn: 0, secEnd: 18, fork: [0, 0, 0], join: [0, 0, 0], lead: 14 }; // no trunk: just the section branch
const GREEN = "#0a7a4b", GREY = "rgba(11,16,21,.22)", NODE = "rgba(11,16,21,.45)";

// Geometry is measured from the rendered links (rects, not offsetTop, so fractional line heights stay exact), so the tree
// follows wrapping, fonts and window size. It re-measures on mount (= when the drawer / sheet opens), resize and font load;
// `animationend` bubbling to the root (the rail's stagger) calls the returned measure again once transforms settle.
// `topOf` gives where the trunk starts, or null when it can't be drawn yet.
function useTree(topOf: (root: HTMLElement, R: DOMRect) => number | null) {
  const ref = useRef<HTMLDivElement>(null);
  const [geo, setGeo] = useState<Geo | null>(null);

  const measure = useCallback(() => {
    const root = ref.current;
    if (!root || root.offsetParent === null) return; // hidden (rail below 1024px): nothing to draw
    const R = root.getBoundingClientRect();
    const top = topOf(root, R);
    if (top === null) return;
    const cy = (el: Element) => { const r = el.getBoundingClientRect(); return r.top - R.top + r.height / 2; };
    const next: Geo = {
      w: R.width,
      h: root.scrollHeight,
      top,
      links: Array.from(root.querySelectorAll(".nav-g > a")).map((a) => ({ y: cy(a), on: a.getAttribute("aria-current") === "page" })),
      secs: Array.from(root.querySelectorAll(".tb a")).map(cy),
    };
    setGeo((g) => (g && JSON.stringify(g) === JSON.stringify(next) ? g : next));
  }, [topOf]);

  useLayoutEffect(() => {
    measure();
    const root = ref.current;
    if (!root) return;
    const ro = new ResizeObserver(measure);
    ro.observe(root);
    window.addEventListener("resize", measure);
    document.fonts?.ready.then(measure);
    return () => { ro.disconnect(); window.removeEventListener("resize", measure); };
  }, [measure]);

  return { ref, geo, measure };
}

const railTop = (root: HTMLElement, R: DOMRect) => {
  const logo = root.querySelector(".logo svg");
  return logo ? logo.getBoundingClientRect().bottom - R.top + 10 : null;
};
const zeroTop = () => 0;

// The branch-tree lines: an aria-hidden SVG over the nav. Which section is current comes from the scroll spy (`active`).
function TreeSvg({ geo, cur, cfg, className }: { geo: Geo; cur: number; cfg: TreeCfg; className: string }) {
  const { links, secs } = geo;
  if (!links.length && !secs.length) return null;
  const { X, BX } = cfg;
  const act = links.find((l) => l.on);
  const lastSec = secs[secs.length - 1];
  // with a trunk the branch forks off the current page's node and rejoins the trunk a little below its last section;
  // the trunk runs at least that far. Without a trunk (the sheet) it is just the branch.
  const trunk = links.length > 0;
  const merge = act && secs.length ? lastSec + cfg.join[2] : 0;
  const end = trunk ? Math.max(links[links.length - 1].y, merge) : 0;
  const ci = Math.min(cur, secs.length - 1);
  return (
    <svg className={className} aria-hidden="true" width={geo.w} height={geo.h} focusable="false">
      {trunk && <path d={`M${X} ${geo.top}V${end}`} stroke={GREY} strokeWidth={1} fill="none" />}
      {links.map((l, i) => l.on ? (
        <g key={i}>
          <rect x={X - 3.5} y={l.y - 3.5} width={7} height={7} fill={GREEN} />
          <path d={`M${X + 4} ${l.y}H${cfg.tickOn}`} stroke={GREEN} strokeWidth={1} />
        </g>
      ) : (
        <g key={i}>
          <rect x={X - 2.5} y={l.y - 2.5} width={5} height={5} fill="#fff" stroke={NODE} strokeWidth={1} />
          <path d={`M${X + 4} ${l.y}H${cfg.tick}`} stroke={GREY} strokeWidth={1} />
        </g>
      ))}
      {secs.length > 0 && (act || !trunk) && (
        <g>
          {act
            ? <path d={`M${X} ${act.y}C${X} ${act.y + cfg.fork[0]},${BX} ${act.y + cfg.fork[1]},${BX} ${act.y + cfg.fork[2]}V${secs[ci]}`} stroke={GREEN} strokeWidth={1.5} fill="none" />
            : <path d={`M${BX} ${secs[0] - cfg.lead}V${secs[ci]}`} stroke={GREEN} strokeWidth={1.5} fill="none" />}
          <path d={`M${BX} ${secs[ci]}V${lastSec}${act ? `C${BX} ${lastSec + cfg.join[0]},${X} ${lastSec + cfg.join[1]},${X} ${merge}` : ""}`} stroke={GREY} strokeWidth={1} fill="none" strokeDasharray="2 3" />
          {secs.map((y, k) => (
            <g key={k}>
              {k < ci ? <rect x={BX - 2} y={y - 2} width={4} height={4} fill={GREEN} />
                : k === ci ? <>
                  <rect x={BX - 3.5} y={y - 3.5} width={7} height={7} fill="#fff" stroke={GREEN} strokeWidth={1.5} />
                  <rect x={BX - 1} y={y - 1} width={2} height={2} fill={GREEN} />
                </>
                : <rect x={BX - 2} y={y - 2} width={4} height={4} fill="#fff" stroke="rgba(11,16,21,.4)" strokeWidth={1} />}
              <path d={`M${BX + (k === ci ? 5 : 3)} ${y}H${cfg.secEnd}`} stroke={k <= ci ? GREEN : GREY} strokeWidth={1} />
            </g>
          ))}
        </g>
      )}
    </svg>
  );
}

const curOf = (toc: Toc[], active: string) => Math.max(0, toc.findIndex((t) => t.id === active));

function RailInner({ toc, active }: { toc: Toc[]; active: string }) {
  const { ref, geo, measure } = useTree(railTop);
  return (
    <div className="rail-in" ref={ref} onAnimationEnd={measure}>
      <Logo />
      <Nav toc={toc} active={active} />
      {geo && <TreeSvg geo={geo} cur={curOf(toc, active)} cfg={RAIL} className="rail-tree" />}
    </div>
  );
}

// Phone drawer: the same tree as the rail, in phone sizes. It is mounted only while open, so it measures on open; on open it
// also scrolls so the current page is in view.
function Drawer({ toc, active, onNav }: { toc: Toc[]; active: string; onNav: () => void }) {
  const { ref, geo } = useTree(zeroTop);
  const box = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    const d = box.current, a = d?.querySelector<HTMLElement>('a[aria-current="page"]');
    if (!d || !a) return;
    const y = a.getBoundingClientRect().top - d.getBoundingClientRect().top + d.scrollTop;
    if (y > 120) d.scrollTop = y - 72;
  }, []);
  return (
    <div className="drawer" id="drawer" ref={box}>
      <div className="drawer-in" ref={ref}>
        <Nav onNav={onNav} toc={toc} active={active} stagger={false} />
        {geo && <TreeSvg geo={geo} cur={curOf(toc, active)} cfg={DRAWER} className="m-tree" />}
      </div>
    </div>
  );
}

// "On this page" under the section bar: just the section branch.
function Sheet({ toc, active, onNav }: { toc: Toc[]; active: string; onNav: () => void }) {
  const { ref, geo } = useTree(zeroTop);
  const box = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    const s = box.current, a = s?.querySelector<HTMLElement>(".tb a.on");
    if (!s || !a) return;
    const y = a.getBoundingClientRect().top - s.getBoundingClientRect().top + s.scrollTop;
    s.scrollTop = Math.max(0, y - s.clientHeight / 2 + a.offsetHeight / 2);
  }, []);
  return (
    <>
      <div className="sbsheet-bd" onClick={onNav} aria-hidden="true" />
      <div className="sbsheet" id="sbsheet" ref={box}>
        <div className="sbsheet-in" ref={ref}>
          <div className="label sbsheet-h">On this page</div>
          <ul className="tb" aria-label="On this page">
            {toc.map((t) => (
              <li key={t.id}><a href={`#${t.id}`} className={active === t.id ? "on" : ""} onClick={onNav}>{t.label}</a></li>
            ))}
          </ul>
          {geo && <TreeSvg geo={geo} cur={curOf(toc, active)} cfg={SHEET} className="m-tree" />}
        </div>
      </div>
    </>
  );
}

const NARROW = "(max-width: 1023.98px)"; // below this the rail is replaced by the topbar, drawer and section bar

export function Shell({ children, toc, mdUrl }: { children: React.ReactNode; toc: Toc[]; mdUrl: string }) {
  const [active, setActive] = useState(toc[0].id);
  // one panel at a time on phones and tablets: the Menu drawer or the section sheet
  const [panel, setPanel] = useState<null | "menu" | "sections">(null);
  const path = (usePathname() || "/").replace(/\/?$/, "/");
  const page = RAIL_GROUPS.flatMap((g) => g.items).find((n) => !n.ext && n.href === path)?.label;
  const showBar = path !== "/" && !!page && toc.length > 1; // not on Home (it has no sections to read as a doc)
  const progress = useRef<HTMLDivElement>(null);
  const menuBtn = useRef<HTMLButtonElement>(null);
  const barBtn = useRef<HTMLButtonElement>(null);
  const close = useCallback(() => setPanel(null), []);

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

  // scroll spy (and the section bar's progress line, in the same frame)
  useEffect(() => {
    // measured at most once per frame, and only announced when the section changes (Safari fires scroll often)
    const narrow = window.matchMedia(NARROW);
    let raf = 0, prev = "", prevP = -1;
    const measure = () => {
      raf = 0;
      // phones: a section counts as reached once its heading is under the bar (anchors land at 112px); desktop: 35% down
      const line = narrow.matches ? 140 : window.innerHeight * 0.35;
      let cur = toc[0].id;
      for (const s of toc) { const e = document.getElementById(s.id); if (e && e.getBoundingClientRect().top <= line) cur = s.id; }
      const bar = progress.current;
      if (bar && narrow.matches) {
        const max = document.documentElement.scrollHeight - window.innerHeight;
        const p = max > 0 ? Math.min(1, Math.max(0, window.scrollY / max)) : 0;
        if (Math.abs(p - prevP) > 0.0005) { prevP = p; bar.style.transform = `scaleX(${p.toFixed(4)})`; }
      }
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

  // Escape closes the open panel and hands focus back to its button; the drawer locks the page behind it;
  // growing to the desktop layout (where the rail takes over) closes both
  useEffect(() => {
    const narrow = window.matchMedia(NARROW);
    const wide = (e: MediaQueryListEvent) => { if (!e.matches) setPanel(null); };
    narrow.addEventListener("change", wide);
    return () => narrow.removeEventListener("change", wide);
  }, []);
  useEffect(() => {
    if (!panel) return;
    const from = panel;
    const key = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      setPanel(null);
      (from === "menu" ? menuBtn : barBtn).current?.focus();
    };
    document.addEventListener("keydown", key);
    if (panel === "menu") document.documentElement.classList.add("lock");
    return () => { document.removeEventListener("keydown", key); document.documentElement.classList.remove("lock"); };
  }, [panel]);

  return (
    <>
      <BgDelta />
      <aside className="rail" aria-label="Site">
        <RailInner toc={toc} active={active} />
      </aside>
      <div className="edge" aria-hidden="true" />
      <header className="topbar">
        <Logo />
        <button className="menu-btn" ref={menuBtn} aria-expanded={panel === "menu"} aria-controls="drawer" onClick={() => setPanel(panel === "menu" ? null : "menu")}>{panel === "menu" ? "Close" : "Menu"}</button>
      </header>
      {showBar && (
        <div className="sbar">
          <button className="sbar-t" ref={barBtn} aria-expanded={panel === "sections"} aria-controls="sbsheet" onClick={() => setPanel(panel === "sections" ? null : "sections")}>
            <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true" focusable="false">
              <path d="M1 9H13" stroke="rgba(11,16,21,.35)" fill="none" />
              <rect x="5" y="6" width="6" height="6" fill="#fff" stroke={GREEN} strokeWidth="1.5" />
            </svg>
            <span className="pg">{page}<span aria-hidden="true"> ›</span></span>
            <span className="cur">{toc.find((t) => t.id === active)?.label ?? toc[0].label}</span>
            <span className="chev label">{panel === "sections" ? "Close ▴" : "Sections ▾"}</span>
          </button>
          <div className="prog" ref={progress} aria-hidden="true" />
        </div>
      )}
      {panel === "menu" && <Drawer toc={toc} active={active} onNav={close} />}
      {showBar && panel === "sections" && <Sheet toc={toc} active={active} onNav={close} />}
      <main className="main">
        <div className="col">
          {children}
        </div>
      </main>
    </>
  );
}
