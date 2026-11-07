"use client";

import { useReduced } from "@/lib/useReduced";
import { useRef } from "react";
import { motion, useInView } from "motion/react";
import { Section, Eyebrow, H2 } from "./ui/Section";
import { Rich } from "./ui/Rich";
import { Frame } from "./ui/Frame";
import { DAMAGE_QUESTIONS, QUESTIONS, SAFETY } from "@/content";

const CX = 280;
const CY = 225;
const R = 150;
const rad = (deg: number) => (deg * Math.PI) / 180;
const pt = (deg: number, r: number) => [CX + r * Math.cos(rad(deg)), CY + r * Math.sin(rad(deg))] as const;

function Radar() {
  const ref = useRef<SVGSVGElement>(null);
  const inView = useInView(ref, { once: true, amount: 0.4 });
  const reduce = useReduced();
  const on = inView || !!reduce;
  return (
    <svg
      ref={ref}
      viewBox="0 0 560 450"
      className="mx-auto h-auto w-full max-w-[520px]"
      role="img"
      aria-label="Six damage questions as a hexagon. Data and Availability fail; Exposure, Money, Control and Outside world pass."
    >
      <defs>
        <radialGradient id="radar-glow" cx="50%" cy="50%" r="50%">
          <stop offset="0" stopColor="#FF5A1F" stopOpacity="0.14" />
          <stop offset="1" stopColor="#FF5A1F" stopOpacity="0" />
        </radialGradient>
      </defs>
      <circle cx={CX} cy={CY} r={R * 1.25} fill="url(#radar-glow)" />
      {[0.33, 0.66, 1].map((k) => (
        <polygon
          key={k}
          points={[0, 1, 2, 3, 4, 5].map((i) => pt(-60 + 60 * i, R * k).join(",")).join(" ")}
          fill="none"
          stroke="rgba(255,255,255,0.09)"
          strokeWidth="1"
        />
      ))}
      {DAMAGE_QUESTIONS.map((q, i) => {
        const mid = -90 + 60 * i;
        const [ax, ay] = pt(mid - 30, R);
        const [bx, by] = pt(mid + 30, R);
        const [lx, ly] = pt(mid, R * 0.87 + 30);
        const [gx, gy] = pt(mid, R * 0.58);
        const bad = !!q.fails;
        const color = bad ? "#FF4D4D" : "#3DDC84";
        const anchor = Math.abs(lx - CX) < 8 ? "middle" : lx > CX ? "start" : "end";
        const Icon = q.icon;
        return (
          <g key={q.name}>
            <motion.polygon
              points={`${CX},${CY} ${ax},${ay} ${bx},${by}`}
              stroke="#0b0b0c"
              strokeWidth="3"
              strokeLinejoin="round"
              initial={{ fill: "rgba(255,255,255,0.035)" }}
              animate={{
                fill: on
                  ? bad
                    ? ["rgba(255,77,77,0.34)", "rgba(255,77,77,0.18)", "rgba(255,77,77,0.34)"]
                    : "rgba(61,220,132,0.2)"
                  : "rgba(255,255,255,0.035)",
              }}
              transition={
                bad && on && !reduce
                  ? { delay: i * 0.3, duration: 2.2, repeat: Infinity, ease: "easeInOut" }
                  : { delay: reduce ? 0 : i * 0.3, duration: 0.5 }
              }
            />
            <motion.foreignObject
              x={gx - 12}
              y={gy - 12}
              width="24"
              height="24"
              initial={{ opacity: 0 }}
              animate={{ opacity: on ? 1 : 0 }}
              transition={{ delay: reduce ? 0 : i * 0.3 + 0.15 }}
            >
              <div style={{ color }} className="flex size-6 items-center justify-center">
                <Icon size={18} strokeWidth={2} />
              </div>
            </motion.foreignObject>
            <text
              x={lx}
              y={ly + 4}
              textAnchor={anchor}
              fontSize="14"
              fontWeight="500"
              fill="#EDEBE6"
              fontFamily="var(--font-inter), sans-serif"
            >
              {q.name}
            </text>
          </g>
        );
      })}
      {[0, 1, 2, 3, 4, 5].map((i) => {
        const [x, y] = pt(-60 + 60 * i, R);
        return <line key={i} x1={CX} y1={CY} x2={x} y2={y} stroke="rgba(255,255,255,0.12)" />;
      })}
    </svg>
  );
}

export function Questions() {
  return (
    <Section aria-labelledby="questions-h" id="safety">
      <div className="mx-auto max-w-[900px] text-center">
        <Eyebrow>{QUESTIONS.eyebrow}</Eyebrow>
        <H2 id="questions-h">
          <Rich text={QUESTIONS.h2} />
        </H2>
        <p className="mx-auto mt-6 max-w-[60ch] text-[17px] leading-relaxed text-muted md:text-lg">{QUESTIONS.sub}</p>
      </div>

      <div className="mt-14 grid items-center gap-10 lg:grid-cols-[1fr_1fr] lg:gap-16">
        <Radar />
        <ul className="grid gap-px overflow-hidden rounded-2xl border border-white/10 bg-white/10">
          {DAMAGE_QUESTIONS.map((q) => {
            const Icon = q.icon;
            return (
              <li key={q.name} className="flex gap-4 bg-[#0d0d0f] px-5 py-4">
                <span className="mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-lg border border-white/10 bg-white/[0.04] text-forge">
                  <Icon size={17} />
                </span>
                <div className="min-w-0">
                  <p className="font-medium">{q.name}</p>
                  <p className="mt-0.5 text-[14.5px] leading-snug text-muted">{q.question}</p>
                </div>
              </li>
            );
          })}
        </ul>
      </div>
      <p className="mx-auto mt-8 max-w-[64ch] text-center text-[15px] leading-relaxed text-muted">{QUESTIONS.foot}</p>

      <div className="mt-20">
        <p className="mb-6 text-center font-display text-[34px] tracking-[-0.02em] md:text-[44px]">Built to be trusted.</p>
        <Frame radius={22} innerClassName="bg-[#0d0d0f]/90">
          <ul className="grid gap-px bg-white/[0.07] sm:grid-cols-2 lg:grid-cols-3 [&>li]:bg-[#0d0d0f]">
            {SAFETY.map((s) => {
              const Icon = s.icon;
              return (
                <li key={s.title} className="p-6">
                  <Icon size={20} className="text-forge" aria-hidden="true" />
                  <p className="mt-3 font-semibold">{s.title}</p>
                  <p className="mt-1.5 text-[14.5px] leading-relaxed text-muted">
                    <Rich text={s.body} />
                  </p>
                </li>
              );
            })}
          </ul>
        </Frame>
      </div>
    </Section>
  );
}
