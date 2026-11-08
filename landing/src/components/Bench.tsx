"use client";

import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { BENCH, SWITCHES, type SwitchDef, type Verdict } from "@/content";
import { cn } from "@/lib/cn";
import { useReduced } from "@/lib/useReduced";
import { DiagramSvg, diagramText } from "./Diagram";
import { switchOf, useLab, type Test } from "./LabProvider";
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
  ready,
  onPress,
}: {
  sw: SwitchDef;
  open: boolean;
  thrown: boolean;
  tested: boolean;
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
      aria-label={`Run test: ${sw.action}`}
      disabled={!ready}
      onClick={onPress}
      className="sw relative flex cursor-pointer flex-col rounded-md border-2 border-black bg-white p-2.5 text-left disabled:cursor-not-allowed disabled:opacity-70"
    >
      <span className="flex items-center justify-between font-mono text-[11px] leading-none text-ink-3">
        <span aria-hidden="true">{String(sw.id).padStart(2, "0")}</span>
        <span
          aria-hidden="true"
          className="size-2.5 rounded-full border-2 border-black"
          style={{ background: tested ? LAMP[sw.verdict] : "#fff" }}
        />
      </span>
      <span className="relative mx-auto mt-2 block h-12 w-full">
        <span aria-hidden="true" className="absolute left-1/2 top-1/2 block h-11 w-[26px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-black">
          <span className="sw-lever" />
        </span>
        <span aria-hidden="true" className="sw-cover" />
      </span>
      <span className="mt-2.5 block text-[13.5px] font-medium leading-[1.25]">
        {sw.line1}
        <span className="block font-mono text-[11.5px] font-normal text-ink-2">{sw.line2}</span>
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

  useEffect(() => {
    const t = timers.current;
    return () => t.forEach(clearTimeout);
  }, []);

  function reveal() {
    requestAnimationFrame(() =>
      reportRef.current?.scrollIntoView({ block: "nearest", behavior: reduced ? "auto" : "smooth" }),
    );
  }

  function run(id: number) {
    dispatch({ type: "run", switchId: id });
    setArming(null);
    reveal();
  }

  function press(sw: SwitchDef) {
    if (arming) return;
    const done = state.tests.find((t) => t.switchId === sw.id);
    if (done) {
      dispatch({ type: "select", view: done.n });
      reveal();
      return;
    }
    if (reduced) return run(sw.id);
    // cover flips up (180ms), the toggle throws (150ms), then the test runs
    setArming({ id: sw.id, phase: "cover" });
    timers.current.push(
      setTimeout(() => setArming({ id: sw.id, phase: "toggle" }), 180),
      setTimeout(() => run(sw.id), 360),
    );
  }

  const view = state.selected;
  const branchTest: Test | null = view === "live" ? null : (state.tests.find((t) => t.n === view) ?? null);
  const branchSw = branchTest ? switchOf(branchTest.switchId) : null;
  const damage = branchSw?.damage ?? null;
  const first = SWITCHES[0];
  const note = branchTest ? BENCH.branchNote : BENCH.liveNote;

  return (
    <div className="rounded-[10px] border-2 border-black bg-bench p-3 sm:p-5">
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

      {/* b) the switch panel */}
      <div className="mt-4 grid grid-cols-2 gap-x-3 gap-y-5 pt-3 sm:grid-cols-4 sm:gap-x-4">
        {SWITCHES.map((sw) => {
          const tested = state.tests.some((t) => t.switchId === sw.id);
          const mine = arming?.id === sw.id;
          return (
            <GuardedSwitch
              key={sw.id}
              sw={sw}
              open={mine}
              thrown={mine && arming?.phase === "toggle"}
              tested={tested}
              ready={ready}
              onPress={() => press(sw)}
            />
          );
        })}
        <div className="flex flex-col justify-center gap-2 px-1 font-mono text-[12px] text-ink-2">
          <span data-js>
            {state.tests.length} of {SWITCHES.length} thrown
          </span>
          <button
            type="button"
            data-js
            disabled={!ready || state.tests.length === 0}
            onClick={() => dispatch({ type: "reset" })}
            className="label w-fit rounded-sm underline underline-offset-4 enabled:hover:text-block disabled:text-ink-3 disabled:no-underline"
          >
            {BENCH.reset}
          </button>
          <noscript>
            <span className="font-medium text-black">{BENCH.noJs}</span>
          </noscript>
        </div>
      </div>

      {/* c) the test report */}
      <div ref={reportRef} className="mt-5 scroll-mb-4">
        <div data-js>
          <Report test={shown} />
        </div>
        <noscript>
          <Sheet test={{ n: 1, switchId: first.id }} shown={7} animate={false} />
        </noscript>
      </div>
    </div>
  );
}
