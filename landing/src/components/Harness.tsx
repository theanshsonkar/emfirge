"use client";

import { useReduced } from "@/lib/useReduced";
import { useRef } from "react";
import { motion, useInView } from "motion/react";
import { Section, Eyebrow, H2 } from "./ui/Section";
import { Rich } from "./ui/Rich";
import { Frame } from "./ui/Frame";
import { cn } from "@/lib/cn";
import { BENTO, EMFIRGE_MD, HARNESS, SIGNAL } from "@/content";

function Tile({
  className,
  tile,
  center,
  children,
}: {
  center?: boolean;
  className?: string;
  tile: { coding: string; name: string; body: string };
  children: React.ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  function move(e: React.PointerEvent) {
    const el = ref.current;
    if (!el || e.pointerType !== "mouse") return;
    const r = el.getBoundingClientRect();
    el.style.setProperty("--mx", `${e.clientX - r.left}px`);
    el.style.setProperty("--my", `${e.clientY - r.top}px`);
  }
  return (
    <Frame hover radius={22} className={cn("min-w-0", className)} innerClassName="h-full bg-[#0f0f11]">
      <div ref={ref} onPointerMove={move} className="relative flex h-full flex-col p-6 md:p-7">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 hidden opacity-0 transition-opacity duration-300 [@media(hover:hover)]:block [@media(hover:hover)]:group-hover/frame:opacity-100"
          style={{
            background:
              "radial-gradient(420px circle at var(--mx, 50%) var(--my, 50%), rgba(255,90,31,0.11), transparent 60%)",
          }}
        />
        <div className="relative">
          <p className="font-mono text-[11px] uppercase tracking-[0.12em] text-muted">
            {tile.coding} <span className="text-forge">→</span>
          </p>
          <h3 className="mt-1.5 font-display text-[34px] leading-none tracking-[-0.01em]">{tile.name}</h3>
          <p className="mt-3 max-w-[44ch] text-[14.5px] leading-relaxed text-muted">{tile.body}</p>
        </div>
        <div className="relative mt-6 flex min-h-0 flex-1 flex-col justify-end md:[&[data-center]]:justify-center" data-center={center || undefined}>{children}</div>
      </div>
    </Frame>
  );
}

/* --- Context: mini graph with a selected node --- */
function ContextArt() {
  const nodes = [
    { id: "cdn", x: 14, y: 100 },
    { id: "web-alb", x: 142, y: 100 },
    { id: "api-1", x: 270, y: 50 },
    { id: "api-2", x: 270, y: 150 },
    { id: "orders-db", x: 440, y: 100, sel: true },
    { id: "nightly-sync", x: 270, y: 0 },
  ];
  const w = 104;
  const h = 34;
  const edge = (a: string, b: string, hot?: boolean) => {
    const A = nodes.find((n) => n.id === a)!;
    const B = nodes.find((n) => n.id === b)!;
    const x1 = A.x + w, y1 = A.y + h / 2, x2 = B.x, y2 = B.y + h / 2, dx = (x2 - x1) / 2;
    return (
      <path
        key={a + b}
        d={`M${x1} ${y1} C${x1 + dx} ${y1} ${x2 - dx} ${y2} ${x2} ${y2}`}
        fill="none"
        stroke={hot ? "#FF5A1F" : "rgba(237,235,230,0.2)"}
        strokeWidth={hot ? 1.8 : 1.3}
      />
    );
  };
  return (
    <svg viewBox="0 0 580 230" className="h-auto w-full" aria-hidden="true">
      {edge("cdn", "web-alb")}
      {edge("web-alb", "api-1")}
      {edge("web-alb", "api-2")}
      {edge("api-1", "orders-db", true)}
      {edge("api-2", "orders-db", true)}
      {edge("nightly-sync", "orders-db", true)}
      {nodes.map((n) => (
        <g key={n.id}>
          {n.sel && <rect x={n.x - 6} y={n.y - 6} width={w + 12} height={h + 12} rx={14} fill="rgba(255,90,31,0.12)" />}
          <rect
            x={n.x}
            y={n.y}
            width={w}
            height={h}
            rx={9}
            fill="#151518"
            stroke={n.sel ? "#FF5A1F" : "rgba(237,235,230,0.18)"}
            strokeWidth={n.sel ? 1.6 : 1}
          />
          <circle cx={n.x + 14} cy={n.y + h / 2} r={4} fill={n.sel ? "#FF5A1F" : "rgba(237,235,230,0.35)"} />
          <text x={n.x + 26} y={n.y + h / 2 + 4} fontSize="11" fill="#EDEBE6" fontFamily="var(--font-jetbrains), monospace">
            {n.id}
          </text>
        </g>
      ))}
      <g transform="translate(384 150)">
        <rect width="196" height="46" rx="10" fill="#1b1b1f" stroke="rgba(255,255,255,0.18)" />
        <text x="12" y="19" fontSize="11" fill="#EDEBE6" fontWeight="600" fontFamily="var(--font-jetbrains), monospace">
          {BENTO.context.tooltip[0]}
        </text>
        <text x="12" y="35" fontSize="10.5" fill="#8E8C86" fontFamily="var(--font-jetbrains), monospace">
          {BENTO.context.tooltip[1]}
        </text>
        <path d="M60 0 l6 -8 l6 8" fill="#1b1b1f" stroke="rgba(255,255,255,0.18)" />
        <path d="M59 1 h14" stroke="#1b1b1f" strokeWidth="2" />
      </g>
    </svg>
  );
}

/* --- Branch: main line + forked line --- */
function BranchArt() {
  const ref = useRef<SVGSVGElement>(null);
  const inView = useInView(ref, { once: true, amount: 0.5 });
  const reduce = useReduced();
  const on = inView || !!reduce;
  return (
    <svg ref={ref} viewBox="0 0 320 130" className="h-auto w-full" aria-hidden="true">
      <text x="0" y="14" fontSize="10.5" fill="#8E8C86" fontFamily="var(--font-jetbrains), monospace">live</text>
      <line x1="34" y1="10" x2="312" y2="10" stroke="rgba(237,235,230,0.25)" strokeWidth="2" />
      {[34, 100, 170, 250, 312].map((x) => (
        <circle key={x} cx={x} cy="10" r="4.5" fill="#0f0f11" stroke="rgba(237,235,230,0.6)" strokeWidth="1.6" />
      ))}
      <motion.path
        d="M100 10 C100 60 130 90 170 90 H300"
        fill="none"
        stroke="#FF5A1F"
        strokeWidth="2"
        strokeLinecap="round"
        initial={{ pathLength: 0 }}
        animate={{ pathLength: on ? 1 : 0 }}
        transition={{ duration: reduce ? 0 : 1.1, ease: "easeInOut" }}
      />
      {[170, 240, 300].map((x, i) => (
        <motion.circle
          key={x}
          cx={x}
          cy="90"
          r="4.5"
          fill="#FF5A1F"
          initial={{ scale: 0 }}
          animate={{ scale: on ? 1 : 0 }}
          style={{ transformBox: "fill-box", transformOrigin: "center" }}
          transition={{ delay: reduce ? 0 : 0.5 + i * 0.2, type: "spring", stiffness: 400, damping: 18 }}
        />
      ))}
      <text x="0" y="116" fontSize="10.5" fill="#FF7A47" fontFamily="var(--font-jetbrains), monospace">branch #1</text>
    </svg>
  );
}

export function Harness() {
  const b = BENTO;
  return (
    <Section id="harness" aria-labelledby="harness-h" className="pb-8 md:pb-12">
      <div className="mx-auto max-w-[760px] text-center">
        <Eyebrow>{HARNESS.eyebrow}</Eyebrow>
        <H2 id="harness-h">
          <Rich text={HARNESS.h2} />
        </H2>
        <p className="mt-6 text-[17px] leading-relaxed text-muted md:text-lg">{HARNESS.lead}</p>
      </div>

      <div className="mt-14 grid gap-4 md:grid-cols-6 md:gap-5">
        <Tile tile={b.context} center className="md:col-span-4 md:row-span-2">
          <ContextArt />
        </Tile>
        <Tile tile={b.branch} className="md:col-span-2">
          <BranchArt />
        </Tile>
        <Tile tile={b.signals} className="md:col-span-2">
          <div className="rounded-xl border border-white/10 bg-black/40 p-4 font-mono text-[12px] leading-[1.65]">
            <p>
              <span className="font-bold text-block">{SIGNAL.status}</span> <span className="text-paper">{SIGNAL.title}</span>
            </p>
            {SIGNAL.lines.slice(0, 3).map((l) => (
              <p key={l} className="break-words text-muted">{l}</p>
            ))}
          </div>
        </Tile>
        <Tile tile={b.boundaries} className="md:col-span-3">
          <div className="rounded-xl border border-white/10 bg-black/40 p-4 font-mono text-[12px] leading-[1.7]">
            <p className="mb-1 text-muted">emfirge.md</p>
            {EMFIRGE_MD.map((l, i) => (
              <p key={l} className={i === 0 ? "text-forge" : "text-paper/90"}>{l}</p>
            ))}
          </div>
        </Tile>
        <Tile tile={b.record} className="md:col-span-3">
          <ol className="relative space-y-6 pl-6 font-mono text-[13px]">
            <span aria-hidden="true" className="absolute bottom-2 left-[5px] top-2 w-px bg-gradient-to-b from-white/25 to-white/5" />
            {b.record.events.map((e) => (
              <li key={e.text} className="relative flex flex-wrap items-baseline gap-x-3">
                <span
                  aria-hidden="true"
                  className={cn(
                    "absolute -left-6 top-[5px] size-[11px] rounded-full border-2 border-[#0f0f11]",
                    e.tone === "pass" ? "bg-pass" : "bg-muted",
                  )}
                />
                <span className="text-muted">{e.time}</span>
                <span className="text-paper">{e.text}</span>
                {e.tag && <span className="font-bold text-pass">{e.tag}</span>}
              </li>
            ))}
          </ol>
        </Tile>
      </div>
    </Section>
  );
}
