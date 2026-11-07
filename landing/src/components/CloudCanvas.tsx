"use client";

import { useReduced } from "@/lib/useReduced";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  AnimatePresence,
  motion,
  useInView,
  useScroll,
  useSpring,
  useTransform,
} from "motion/react";
import { Frame } from "./ui/Frame";
import { cn } from "@/lib/cn";
import {
  CANVAS_ARIA,
  CANVAS_EDGES,
  CANVAS_NODES,
  CANVAS_REDUCED_STEP,
  CANVAS_RESET_PAUSE_MS,
  CANVAS_SCRIPT,
  CANVAS_STORY_TEXT,
  CANVAS_TABS,
  KIND,
  LAYOUT,
  type CanvasNode,
  type CanvasStep,
  type ChipTone,
  type LayoutId,
  type NodeId,
  type Tone,
  type TermLine,
} from "@/content";

/* ------------------------------------------------------------------ */
/* Terminal rows                                                       */
/* ------------------------------------------------------------------ */

const TONE: Record<Tone, string> = {
  paper: "text-paper",
  muted: "text-muted",
  forge: "text-forge",
  pass: "text-pass",
  block: "text-block",
};
const TYPE_MS = 24;
const typedLength = (l: TermLine) => l.segs.reduce((a, s) => a + s.text.length, 0);

function TermRow({ line, reduce, delay }: { line: TermLine; reduce: boolean; delay: number }) {
  const full = typedLength(line);
  const typing = !!line.type && !reduce;
  const [n, setN] = useState(typing ? 0 : full);

  useEffect(() => {
    if (!typing) return;
    let id: ReturnType<typeof setInterval> | undefined;
    const t = setTimeout(() => {
      let i = 0;
      id = setInterval(() => {
        i += 1;
        setN(i);
        if (i >= full && id) clearInterval(id);
      }, TYPE_MS);
    }, 120);
    return () => {
      clearTimeout(t);
      if (id) clearInterval(id);
    };
  }, [typing, full]);

  let left = n;
  return (
    <motion.div
      layout="position"
      initial={reduce ? false : { opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.28, delay: reduce ? 0 : delay, ease: "easeOut", layout: { duration: 0.3 } }}
      className="flex gap-3"
    >
      <span
        className={cn(
          "w-[7.5ch] shrink-0 whitespace-nowrap",
          line.who === "you" ? "text-paper" : "text-muted",
        )}
      >
        {line.who ? `${line.who} ›` : ""}
      </span>
      <span className="min-w-0 whitespace-pre-wrap break-words">
        {line.segs.map((s, j) => {
          const take = Math.max(0, Math.min(left, s.text.length));
          left -= take;
          return (
            <span key={j} className={cn(TONE[s.tone ?? "paper"], s.bold && "font-bold")}>
              {s.text.slice(0, take)}
            </span>
          );
        })}
      </span>
    </motion.div>
  );
}

function AgentPanel({
  step,
  cycle,
  reduce,
  className,
}: {
  step: number;
  cycle: number;
  reduce: boolean;
  className?: string;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const innerRef = useRef<HTMLDivElement>(null);
  // keep the newest line in view: follow the content as it grows
  useEffect(() => {
    const sc = scrollRef.current;
    const inner = innerRef.current;
    if (!sc || !inner) return;
    const follow = () => {
      sc.scrollTop = sc.scrollHeight;
    };
    follow();
    const ro = new ResizeObserver(follow);
    ro.observe(inner);
    return () => ro.disconnect();
  }, []);
  const rows: { line: TermLine; key: string; delay: number }[] = [];
  CANVAS_SCRIPT.slice(0, step + 1).forEach((s, si) => {
    const lead = s.lines[0];
    const afterTyping = lead?.type ? (typedLength(lead) * TYPE_MS) / 1000 + 0.3 : 0.1;
    s.lines.forEach((line, li) => {
      rows.push({ line, key: `${cycle}-${si}-${li}`, delay: li === 0 ? 0 : afterTyping + (li - 1) * 0.16 });
    });
  });
  return (
    <div className={cn("flex min-h-0 flex-col border-t border-white/[0.07] bg-[#0b0b0d]/80 lg:border-l lg:border-t-0", className)}>
      <div className="flex h-11 shrink-0 items-center gap-2 border-b border-white/[0.07] px-4">
        <span className="size-1.5 rounded-full bg-pass" aria-hidden="true" />
        <span className="truncate font-mono text-[11px] text-muted">~/infra — claude</span>
      </div>
      <div
        ref={scrollRef}
        aria-hidden="true"
        className="relative min-h-0 flex-1 overflow-hidden px-4 pb-4 pt-5 font-mono text-[12px] leading-[1.55] [mask-image:linear-gradient(to_bottom,transparent,#000_18px)] sm:text-[12.5px]"
      >
        <div ref={innerRef} className="space-y-1.5">
          {rows.map((r, i) => {
            const startsExchange = r.line.who && i > 0;
            return (
              <div key={r.key} className={cn(startsExchange && "pt-2.5")}>
                <TermRow line={r.line} reduce={reduce} delay={r.delay} />
              </div>
            );
          })}
          <div className="flex gap-3">
            <span className="w-[7.5ch] shrink-0 whitespace-nowrap text-muted">agent ›</span>
            <span
              className={cn("mt-[3px] inline-block h-[13px] w-[7px] bg-forge/90", !reduce && "animate-blink")}
            />
          </div>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Stage: nodes, edges, callouts                                       */
/* ------------------------------------------------------------------ */

interface Box {
  x: number;
  y: number;
  w: number;
  h: number;
}

function edgePath(a: Box, b: Box): { d: string; p1: [number, number]; p2: [number, number] } {
  if (b.x >= a.x + a.w - 4) {
    const x1 = a.x + a.w;
    const y1 = a.y + a.h / 2;
    const x2 = b.x;
    const y2 = b.y + b.h / 2;
    const dx = Math.max(36, (x2 - x1) * 0.5);
    return { d: `M${x1} ${y1} C${x1 + dx} ${y1} ${x2 - dx} ${y2} ${x2} ${y2}`, p1: [x1, y1], p2: [x2, y2] };
  }
  const down = b.y > a.y;
  const x1 = a.x + a.w / 2;
  const y1 = down ? a.y + a.h : a.y;
  const x2 = b.x + b.w / 2;
  const y2 = down ? b.y : b.y + b.h;
  const dy = Math.max(30, Math.abs(y2 - y1) * 0.5) * (down ? 1 : -1);
  return { d: `M${x1} ${y1} C${x1} ${y1 + dy} ${x2} ${y2 - dy} ${x2} ${y2}`, p1: [x1, y1], p2: [x2, y2] };
}

function NodeCard({
  node,
  layout,
  ghost,
  gone,
  shake,
  shakeDelay,
  index,
  reduce,
}: {
  node: CanvasNode;
  layout: LayoutId;
  ghost: boolean;
  gone: boolean;
  shake: boolean;
  shakeDelay: number;
  index: number;
  reduce: boolean;
}) {
  const L = LAYOUT[layout];
  const pos = node.pos[layout]!;
  const k = KIND[node.kind];
  const Icon = k.icon;
  const compact = layout === "compact";
  const tint = ghost ? "#FF4D4D" : k.color;
  return (
    <motion.div
      initial={reduce ? false : { opacity: 0, scale: 0.92 }}
      animate={{
        opacity: gone ? 0 : ghost ? 0.72 : 1,
        scale: gone ? 0.9 : 1,
        x: shake && !reduce ? [0, -5, 5, -4, 4, -2, 0] : 0,
      }}
      transition={{
        opacity: { duration: 0.5, delay: reduce ? 0 : 0.08 * index },
        scale: { duration: 0.5 },
        x: { duration: 0.5, delay: shakeDelay },
      }}
      className="absolute"
      style={{ left: pos.x, top: pos.y, width: L.nodeW, height: L.nodeH, pointerEvents: "none" }}
    >
      <div
        className="relative flex h-full items-center gap-2 rounded-xl border px-2 shadow-[0_10px_30px_-12px_rgba(0,0,0,0.8)] transition-[border-color,background] duration-500"
        style={{
          borderColor: ghost ? "rgba(255,77,77,0.55)" : `${k.color}38`,
          background: `linear-gradient(135deg, ${tint}${ghost ? "18" : "1c"}, #131315 62%)`,
        }}
      >
        <span
          className="flex size-7 shrink-0 items-center justify-center rounded-lg border transition-colors duration-500"
          style={{ background: `${tint}22`, borderColor: `${tint}44`, color: tint }}
        >
          <Icon size={compact ? 15 : 16} strokeWidth={2} />
        </span>
        <span className="min-w-0 leading-tight">
          <span
            className="block font-mono text-[9px] uppercase tracking-[0.1em] transition-colors duration-500"
            style={{ color: `${tint}cc` }}
          >
            {k.service}
          </span>
          <span className="relative mt-0.5 block whitespace-nowrap font-mono text-[11px] text-paper">
            {node.id}
            <motion.span
              aria-hidden="true"
              className="absolute left-0 right-0 top-1/2 h-[1.5px] origin-left bg-block"
              initial={false}
              animate={{ scaleX: ghost ? 1 : 0 }}
              transition={{ duration: 0.4, delay: ghost ? 0.25 : 0, ease: "easeOut" }}
            />
          </span>
        </span>
        <motion.span
          aria-hidden="true"
          className="absolute -top-2 right-2 rounded-full border border-block/50 bg-[#2a1214] px-1.5 py-px font-mono text-[8.5px] uppercase tracking-wider text-block"
          initial={false}
          animate={{ opacity: ghost ? 1 : 0, y: ghost ? 0 : 3 }}
          transition={{ duration: 0.3, delay: ghost ? 0.3 : 0 }}
        >
          delete
        </motion.span>
        <motion.span
          aria-hidden="true"
          className="pointer-events-none absolute -inset-[3px] rounded-[15px] border border-dashed border-block/70"
          initial={false}
          animate={{ opacity: ghost ? 1 : 0 }}
          transition={{ duration: 0.4 }}
        />
      </div>
    </motion.div>
  );
}

function Stage({
  stepIdx,
  step,
  layout,
  reduce,
  svgRef,
}: {
  stepIdx: number;
  step: CanvasStep;
  layout: LayoutId;
  reduce: boolean;
  svgRef: React.RefObject<SVGSVGElement | null>;
}) {
  const L = LAYOUT[layout];
  const nodes = useMemo(() => CANVAS_NODES.filter((n) => n.pos[layout]), [layout]);
  const boxes = useMemo(() => {
    const m = new Map<NodeId, Box>();
    nodes.forEach((n) => m.set(n.id, { ...n.pos[layout]!, w: L.nodeW, h: L.nodeH }));
    return m;
  }, [nodes, layout, L.nodeW, L.nodeH]);

  const edges = useMemo(
    () =>
      CANVAS_EDGES.flatMap((e, i) => {
        const a = boxes.get(e.from);
        const b = boxes.get(e.to);
        if (!a || !b) return [];
        return [{ ...e, id: `${e.from}>${e.to}`, ...edgePath(a, b), i }];
      }),
    [boxes],
  );

  const gone = new Set(step.gone ?? []);
  const ghost = new Set(step.ghost ?? []);

  return (
    <div className="absolute left-0 top-0" style={{ width: L.w, height: L.h }}>
      <svg ref={svgRef} width={L.w} height={L.h} viewBox={`0 0 ${L.w} ${L.h}`} className="absolute inset-0 overflow-visible" aria-hidden="true">
        {edges.map((e) => {
          const dead = step.dead?.includes(e.id);
          const hidden = gone.has(e.from) || gone.has(e.to);
          const alive = !dead && !hidden && !ghost.has(e.from) && !ghost.has(e.to);
          const base = e.traffic ? "rgba(237,235,230,0.26)" : "rgba(237,235,230,0.13)";
          return (
            <motion.g key={e.id} initial={false} animate={{ opacity: hidden ? 0 : 1 }} transition={{ duration: 0.5 }}>
              <motion.path
                d={e.d}
                fill="none"
                strokeWidth={1.6}
                strokeLinecap="round"
                strokeDasharray={e.idle ? "2 6" : undefined}
                stroke={base}
                initial={false}
                animate={{ opacity: dead ? 0 : 1 }}
                transition={{ duration: 0.4 }}
              />
              <motion.path
                d={e.d}
                fill="none"
                stroke="#FF4D4D"
                strokeWidth={1.8}
                strokeLinecap="round"
                strokeDasharray="5 6"
                initial={false}
                animate={{ opacity: dead ? 0.95 : 0 }}
                transition={{ duration: 0.4, delay: dead ? 0.15 : 0 }}
              />
              {[e.p1, e.p2].map((p, j) => (
                <circle
                  key={j}
                  cx={p[0]}
                  cy={p[1]}
                  r={3}
                  fill="#0e0e10"
                  stroke={dead ? "#FF4D4D" : "rgba(237,235,230,0.4)"}
                  strokeWidth={1.4}
                />
              ))}
              {e.traffic && !reduce && (
                <motion.g initial={false} animate={{ opacity: alive ? 1 : 0 }} transition={{ duration: 0.3 }}>
                  {[0, 1, 2].map((k) => (
                    <g key={k}>
                      <circle r={7} fill="#FF5A1F" opacity={0.18} />
                      <circle r={2.6} fill="#FF7A47" />
                      <animateMotion
                        dur="2.7s"
                        begin={`${-(k * 0.9 + e.i * 0.31).toFixed(2)}s`}
                        repeatCount="indefinite"
                        path={e.d}
                      />
                    </g>
                  ))}
                </motion.g>
              )}
            </motion.g>
          );
        })}
      </svg>

      {nodes.map((n, i) => (
        <NodeCard
          key={n.id}
          node={n}
          layout={layout}
          ghost={ghost.has(n.id)}
          gone={gone.has(n.id)}
          shake={!!step.shake?.includes(n.id)}
          shakeDelay={0.55}
          index={i}
          reduce={reduce}
        />
      ))}

      <AnimatePresence>
        {step.callouts?.map((c, i) => {
          const p = c.pos[layout];
          const isPass = c.tone === "pass";
          return (
            <motion.div
              key={`${stepIdx}-${i}`}
              initial={reduce ? false : { opacity: 0, scale: 0.82, y: 8 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, transition: { duration: 0.2 } }}
              transition={{ type: "spring", stiffness: 420, damping: 24, delay: reduce ? 0 : c.delay ?? 0 }}
              className={cn(
                "absolute origin-left rounded-lg border px-2.5 py-1.5 font-mono backdrop-blur-sm",
                isPass
                  ? "border-pass/40 bg-[#0d2418]/90 shadow-[0_8px_30px_-10px_rgba(61,220,132,0.5)]"
                  : "border-block/45 bg-[#2a0f12]/90 shadow-[0_8px_30px_-10px_rgba(255,77,77,0.5)]",
              )}
              style={{ left: p.x, top: p.y, width: p.w }}
            >
              <p className={cn("text-[11.5px] font-semibold leading-tight", isPass ? "text-pass" : "text-block")}>
                {isPass ? "✓" : "✗"} {c.head}
              </p>
              <p className="mt-0.5 text-[10.5px] leading-tight text-paper/70">{c.text}</p>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Window                                                              */
/* ------------------------------------------------------------------ */

const CHIP: Record<ChipTone, string> = {
  live: "border-white/15 bg-white/[0.05] text-paper",
  branch: "border-forge/40 bg-forge/10 text-forge",
  block: "border-block/50 bg-block/15 text-block",
  pass: "border-pass/50 bg-pass/15 text-pass",
};
const CHIP_DOT: Record<ChipTone, string> = {
  live: "bg-pass",
  branch: "bg-forge",
  block: "bg-block",
  pass: "bg-pass",
};

export function CloudCanvas() {
  const reduce = useReduced();
  const rootRef = useRef<HTMLDivElement>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const inView = useInView(rootRef, { amount: 0.12 });
  const [hidden, setHidden] = useState(false);
  const [stepIdx, setStepIdx] = useState(0);
  const [cycle, setCycle] = useState(0);
  const [w, setW] = useState(0);

  const active = reduce ? CANVAS_REDUCED_STEP : stepIdx;
  const step = CANVAS_SCRIPT[active];
  const playing = !reduce && inView && !hidden;

  // measure the stage wrapper, pick the layout and scale
  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setW(e.contentRect.width));
    ro.observe(el);
    setW(el.getBoundingClientRect().width);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    const onVis = () => setHidden(document.hidden);
    document.addEventListener("visibilitychange", onVis);
    return () => document.removeEventListener("visibilitychange", onVis);
  }, []);

  // the scripted story loop; stops when offscreen / hidden / reduced motion
  useEffect(() => {
    if (!playing) return;
    const last = stepIdx === CANVAS_SCRIPT.length - 1;
    const t = setTimeout(
      () => {
        if (last) {
          setStepIdx(0);
          setCycle((c) => c + 1);
        } else setStepIdx(stepIdx + 1);
      },
      CANVAS_SCRIPT[stepIdx].ms + (last ? CANVAS_RESET_PAUSE_MS : 0),
    );
    return () => clearTimeout(t);
  }, [playing, stepIdx]);

  // pause the SMIL traffic dots with the story
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg || typeof svg.pauseAnimations !== "function") return;
    if (playing) svg.unpauseAnimations();
    else svg.pauseAnimations();
  }, [playing, w]);

  const layout: LayoutId = w > 0 && w < 640 ? "compact" : "desktop";
  const L = LAYOUT[layout];
  const scale = w > 0 ? w / L.w : 1;

  // 3D tilt: rotateX 11deg -> 0 as the page scrolls
  const { scrollY } = useScroll();
  const raw = useTransform(scrollY, [0, 480], [reduce ? 0 : 11, 0]);
  const tilt = useSpring(raw, { stiffness: 120, damping: 26 });

  return (
    <div ref={rootRef} className="relative">
      <div style={{ perspective: 1800 }}>
        <motion.div style={{ rotateX: tilt, transformOrigin: "50% 0%" }}>
          <Frame radius={20} tone="forge" className="shadow-[0_40px_120px_-30px_rgba(255,90,31,0.45)]" innerClassName="bg-[#0c0c0e]">
            <div role="img" aria-label={CANVAS_ARIA}>
              {/* top bar */}
              <div aria-hidden="true" className="flex h-11 items-center justify-between gap-3 border-b border-white/[0.07] bg-white/[0.02] pl-4 pr-3">
                <div className="flex min-w-0 items-center gap-4">
                  <span className="hidden items-center gap-1.5 sm:flex">
                    <span className="size-2.5 rounded-full bg-white/15" />
                    <span className="size-2.5 rounded-full bg-white/15" />
                    <span className="size-2.5 rounded-full bg-white/15" />
                  </span>
                  <div className="flex items-center gap-1 font-mono text-[11.5px]">
                    {CANVAS_TABS.map((t) => {
                      const exists = step.tabs.includes(t);
                      if (!exists) return null;
                      const isActive = step.tab === t;
                      return (
                        <motion.span
                          key={t}
                          layout
                          initial={reduce ? false : { opacity: 0, scale: 0.85 }}
                          animate={{ opacity: 1, scale: 1 }}
                          transition={{ duration: 0.3 }}
                          className={cn(
                            "relative flex h-7 items-center gap-1.5 rounded-md px-2.5 transition-colors duration-300",
                            isActive ? "text-paper" : "text-muted",
                          )}
                        >
                          {isActive && (
                            <motion.span
                              layoutId="canvas-tab"
                              className={cn(
                                "absolute inset-0 rounded-md border",
                                t === "live" ? "border-white/15 bg-white/[0.08]" : "border-forge/40 bg-forge/10",
                              )}
                              transition={{ type: "spring", stiffness: 500, damping: 36 }}
                            />
                          )}
                          <span className="relative flex items-center gap-1.5">
                            {t !== "live" && <span className={cn("size-1.5 rounded-full", isActive ? "bg-forge" : "bg-muted/60")} />}
                            {t}
                          </span>
                        </motion.span>
                      );
                    })}
                  </div>
                </div>
                <AnimatePresence mode="wait" initial={false}>
                  <motion.span
                    key={step.chip.label}
                    initial={reduce ? false : { opacity: 0, y: -4, scale: 0.94 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: 4, transition: { duration: 0.12 } }}
                    transition={{ duration: 0.22 }}
                    className={cn(
                      "flex h-7 shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border px-3 font-mono text-[11px] font-semibold",
                      CHIP[step.chip.tone],
                    )}
                  >
                    <span className={cn("size-1.5 rounded-full", CHIP_DOT[step.chip.tone])} />
                    {step.chip.label}
                  </motion.span>
                </AnimatePresence>
              </div>

              <div className="grid lg:grid-cols-[minmax(0,1fr)_340px]">
                {/* canvas */}
                <div
                  ref={wrapRef}
                  aria-hidden="true"
                  className="relative overflow-hidden"
                  style={{
                    height: w > 0 ? L.h * scale : undefined,
                    aspectRatio: w > 0 ? undefined : "860 / 500",
                    backgroundColor: "#0b0b0d",
                    backgroundImage:
                      "radial-gradient(rgba(237,235,230,0.14) 1px, transparent 1.3px), radial-gradient(60% 70% at 85% 10%, rgba(42,22,48,0.9), transparent 70%), radial-gradient(50% 60% at 10% 100%, rgba(255,90,31,0.10), transparent 70%)",
                    backgroundSize: "22px 22px, 100% 100%, 100% 100%",
                    backgroundPosition: "10px 10px, 0 0, 0 0",
                  }}
                >
                  <div
                    className="absolute left-0 top-0 origin-top-left transition-opacity duration-300"
                    style={{ width: L.w, height: L.h, transform: `scale(${scale})`, opacity: w > 0 ? 1 : 0 }}
                  >
                    <Stage stepIdx={active} step={step} layout={layout} reduce={reduce} svgRef={svgRef} />
                  </div>
                  <motion.div
                    className="pointer-events-none absolute inset-2 rounded-xl border-2 border-dashed border-forge/60"
                    initial={false}
                    animate={{ opacity: step.branch ? 1 : 0 }}
                    transition={{ duration: 0.5 }}
                  />
                  <div className="pointer-events-none absolute bottom-4 left-4">
                    <AnimatePresence mode="wait">
                      {step.toast && (
                        <motion.div
                          key={`${active}-${step.toast.text}`}
                          initial={reduce ? false : { opacity: 0, y: 10, scale: 0.95 }}
                          animate={{ opacity: 1, y: 0, scale: 1 }}
                          exit={{ opacity: 0, y: 4 }}
                          transition={{ type: "spring", stiffness: 380, damping: 26, delay: reduce ? 0 : 0.25 }}
                          className={cn(
                            "flex items-center gap-2 rounded-full border px-3.5 py-1.5 font-mono text-[11.5px] backdrop-blur-md",
                            step.toast.tone === "pass"
                              ? "border-pass/40 bg-[#0d2418]/85 text-pass"
                              : "border-forge/45 bg-[#2a1409]/85 text-forge",
                          )}
                        >
                          <span className={cn("size-1.5 rounded-full", step.toast.tone === "pass" ? "bg-pass" : "bg-forge")} />
                          {step.toast.text}
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                </div>

                <div className="relative h-[300px] lg:h-auto">
                  <AgentPanel step={active} cycle={cycle} reduce={reduce} className="absolute inset-0" />
                </div>
              </div>
            </div>
          </Frame>
        </motion.div>
      </div>
      <ol className="sr-only">
        {CANVAS_STORY_TEXT.map((t) => (
          <li key={t}>{t}</li>
        ))}
      </ol>
    </div>
  );
}
