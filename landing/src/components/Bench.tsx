"use client";

import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { BENCH, LOOP, SWITCHES, type SwitchDef, type Verdict } from "@/content";
import { cn } from "@/lib/cn";
import { useReduced } from "@/lib/useReduced";
import { DiagramSvg, diagramText } from "./Diagram";
import { LabReport } from "./LabReport";
import { caseOf, useLab, type Test } from "./LabProvider";
import { Report, Sheet } from "./Report";

const noopSubscribe = () => () => {};
/** false on the server and before hydration, so switches stay disabled without JS. */
function useHydrated() {
  return useSyncExternalStore(noopSubscribe, () => true, () => false);
}

const LAMP: Record<Verdict, string> = { blocked: "#E5341D", ask: "#FFD60A", passed: "#1F9D55" };

function GuardedSwitch({
  sw,
  open,
  thrown,
  tested,
  fixed,
  first,
  ready,
  onPress,
}: {
  sw: SwitchDef;
  open: boolean;
  thrown: boolean;
  tested: boolean;
  /** an agent retry of this blocked switch has passed */
  fixed: boolean;
  /** show the "start here" tag */
  first: boolean;
  ready: boolean;
  onPress: () => void;
}) {
  return (
    <button
      type="button"
      data-sw={sw.id}
      data-open={open || tested}
      data-thrown={thrown || tested}
      aria-pressed={tested}
      aria-label={`Run test: ${sw.action}${fixed ? " (fixed by agent)" : ""}`}
      disabled={!ready}
      onClick={onPress}
      className="sw relative flex cursor-pointer flex-col rounded-md border-2 border-black bg-white p-2 text-left disabled:cursor-not-allowed disabled:opacity-70 xl:p-1.5 xl:pb-2"
    >
      {first ? (
        <span
          data-js
          aria-hidden="true"
          className="pointer-events-none absolute -right-2 -top-3.5 z-10 -rotate-[4deg] rounded-[3px] border-[1.5px] border-black bg-crash px-1.5 py-px font-mono text-[12px] leading-[1.3]"
        >
          {BENCH.startHere}
        </span>
      ) : null}
      <span className="flex items-center justify-between px-0.5 font-mono text-[11px] leading-none text-ink-3">
        <span aria-hidden="true">{String(sw.id).padStart(2, "0")}</span>
        <span
          aria-hidden="true"
          className="size-2.5 rounded-full border-2 border-black"
          style={{ background: tested ? LAMP[sw.verdict] : "#fff" }}
        />
      </span>
      <span className="sw-hw mx-auto mt-4 w-full">
        <span aria-hidden="true" className="absolute left-1/2 top-1/2 block h-9 w-[22px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-black">
          <span className="sw-lever" />
        </span>
        <span aria-hidden="true" className="sw-hinge sw-hinge-l" />
        <span aria-hidden="true" className="sw-hinge sw-hinge-r" />
        <span aria-hidden="true" className="sw-cover" />
      </span>
      <span className="mt-2 block px-0.5 text-[13px] font-medium leading-[1.25] xl:px-0">
        {sw.line1}
        <span className="block font-mono text-[11px] font-normal tracking-[-0.02em] text-ink-2 xl:text-[10.5px]">{sw.line2}</span>
      </span>
      <span aria-hidden="true" className="mt-0.5 block h-3 px-0.5 font-mono text-[10px] leading-3 text-ink-3 xl:px-0">
        {fixed ? LOOP.fixedNote : ""}
      </span>
    </button>
  );
}

export function Bench() {
  const { state, dispatch, shown } = useLab();
  const ready = useHydrated();
  const reduced = useReduced();
  const [arming, setArming] = useState<{ id: number; phase: "cover" | "toggle" } | null>(null);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);
  const reportRef = useRef<HTMLDivElement>(null);
  const benchRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const t = timers.current;
    return () => t.forEach(clearTimeout);
  }, []);

  // After every new test, retry, decision or branch pick (the reducer bumps seq): bring the bench into view.
  const seq = state.seq;
  useEffect(() => {
    if (seq === 0) return;
    const id = requestAnimationFrame(() => {
      const behavior = reduced ? "auto" : "smooth";
      const bench = benchRef.current;
      if (!bench) return;
      const r = bench.getBoundingClientRect();
      const barBottom = 40;
      if (bench.offsetHeight + barBottom + 16 <= window.innerHeight) {
        // the whole bench fits: only move if part of it is hidden; then put its top 16px under the bar
        if (r.top < barBottom || r.bottom > window.innerHeight) window.scrollTo({ top: window.scrollY + r.top - (barBottom + 16), behavior });
      } else {
        // smaller viewports: follow the report
        reportRef.current?.scrollIntoView({ block: "nearest", behavior });
      }
    });
    return () => cancelAnimationFrame(id);
  }, [seq, reduced]);

  function run(id: number) {
    dispatch({ type: "run", switchId: id });
    setArming(null);
  }

  function press(sw: SwitchDef) {
    if (arming) return;
    const done = state.tests.find((t) => t.switchId === sw.id && t.retryOf === undefined);
    if (done) {
      dispatch({ type: "select", view: done.n, reveal: true });
      return;
    }
    if (reduced) return run(sw.id);
    // cover flips up (180ms), the toggle throws (120ms), then the test runs
    setArming({ id: sw.id, phase: "cover" });
    timers.current.push(
      setTimeout(() => setArming({ id: sw.id, phase: "toggle" }), 180),
      setTimeout(() => run(sw.id), 300),
    );
  }

  const view = state.selected;
  const branchTest: Test | null = view === "live" ? null : (state.tests.find((t) => t.n === view) ?? null);
  const branchSw = branchTest ? caseOf(branchTest) : null;
  const damage = branchSw?.damage ?? null;
  const first = SWITCHES[0];
  const note = branchTest ? BENCH.branchNote : BENCH.liveNote;

  return (
    <div className="min-w-0">
    <div ref={benchRef} className="scroll-mt-14 rounded-[10px] border-2 border-black bg-bench p-3 sm:p-4 xl:p-5">
      {/* a) the demo cloud */}
      <div data-js>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <div role="group" aria-label="View" className="label flex flex-wrap gap-1.5">
            <button
              type="button"
              aria-pressed={view === "live"}
              onClick={() => dispatch({ type: "select", view: "live" })}
              className={cn(
                "rounded-md border-2 border-black px-3 py-1",
                view === "live" ? "bg-black text-white" : "bg-white hover:bg-rule",
              )}
            >
              live
            </button>
            {state.tests.map((t) => (
              <button
                key={t.n}
                type="button"
                aria-pressed={view === t.n}
                onClick={() => dispatch({ type: "select", view: t.n })}
                className={cn(
                  "branch-in rounded-md border-2 border-black px-3 py-1",
                  view === t.n ? "bg-black text-white" : "bg-white hover:bg-rule",
                )}
              >
                branch #{t.n}
              </button>
            ))}
          </div>
          <p className="font-mono text-[11.5px] text-ink-2 sm:ml-auto">{note}</p>
        </div>
        <div className="mt-3 rounded-md bg-white">
          <div key={`n${String(view)}`} className="sm:hidden">
            <DiagramSvg variant="narrow" damage={damage} target={branchSw?.target ?? null} />
          </div>
          <div key={`w${String(view)}`} className="hidden sm:block">
            <DiagramSvg variant="wide" damage={damage} target={branchSw?.target ?? null} />
          </div>
        </div>
        <p className="sr-only" role="status">
          {view === "live" ? "Live view. " : `Branch ${view}. `}
          {diagramText(damage)}
        </p>
      </div>
      <noscript>
        <div className="rounded-md bg-white">
          <div className="sm:hidden">
            <DiagramSvg variant="narrow" damage={first.damage} target={first.target} />
          </div>
          <div className="hidden sm:block">
            <DiagramSvg variant="wide" damage={first.damage} target={first.target} />
          </div>
        </div>
        <p className="sr-only">Branch 1. {diagramText(first.damage)}</p>
      </noscript>

      {/* b) the switch panel: a row of 7 from 1280px */}
      <div className="mt-4 grid grid-cols-2 gap-x-3 gap-y-5 pt-3 sm:grid-cols-4 sm:gap-x-4 xl:grid-cols-7 xl:gap-x-1.5 xl:pt-2.5">
        {SWITCHES.map((sw) => {
          const tested = state.tests.some((t) => t.switchId === sw.id && t.retryOf === undefined);
          const fixed = state.tests.some((t) => t.switchId === sw.id && t.retryOf !== undefined);
          const mine = arming?.id === sw.id;
          return (
            <GuardedSwitch
              key={sw.id}
              sw={sw}
              open={mine}
              thrown={mine && arming?.phase === "toggle"}
              tested={tested}
              fixed={fixed}
              first={sw.id === 1 && state.tests.length === 0}
              ready={ready}
              onPress={() => press(sw)}
            />
          );
        })}
      </div>
      <div className="mt-2.5 flex items-center gap-3 font-mono text-[12px] text-ink-2">
        <span data-js>{BENCH.thrown(state.tests.filter((t) => t.retryOf === undefined).length, SWITCHES.length)}</span>
        <span data-js aria-hidden="true" className="text-ink-3">
          ·
        </span>
        <button
          type="button"
          data-js
          disabled={!ready || state.tests.length === 0}
          onClick={() => dispatch({ type: "reset" })}
          className="label rounded-sm underline underline-offset-4 enabled:hover:text-block disabled:text-ink-3 disabled:no-underline"
        >
          {BENCH.reset}
        </button>
        <noscript>
          <span className="font-medium text-black">{BENCH.noJs}</span>
        </noscript>
      </div>

      {/* c) the test report */}
      <div ref={reportRef} className="mt-4 scroll-mt-14 scroll-mb-4">
        <div data-js>
          <Report test={shown} />
        </div>
        <noscript>
          <Sheet test={{ n: 1, switchId: first.id }} shown={7} animate={false} />
        </noscript>
      </div>
    </div>
    <LabReport />
    </div>
  );
}
