"use client";

import { useEffect, useState } from "react";
import { BENCH, LOOP, OWNER, QUESTIONS, VERDICT, type Mark, type OwnerDecision } from "@/content";
import { useReduced } from "@/lib/useReduced";
import { cn } from "@/lib/cn";
import { caseOf, isRetryable, useLab, type Test } from "./LabProvider";
import { DecisionStamp, Stamp } from "./Stamp";

const pad = (n: number) => String(n).padStart(3, "0");

function MarkGlyph({ mark }: { mark: Mark | "empty" }) {
  if (mark === "empty") return <span aria-hidden="true" className="block size-3.5 rounded-[3px] border-2 border-rule" />;
  if (mark === "ok")
    return (
      <svg viewBox="0 0 16 16" className="size-4" role="img" aria-label="clear">
        <path d="M2.5 8.5 6.5 12.5 13.5 3.5" fill="none" stroke="#1F9D55" strokeWidth="2.6" strokeLinecap="square" />
      </svg>
    );
  if (mark === "fail")
    return (
      <svg viewBox="0 0 16 16" className="size-4" role="img" aria-label="failed">
        <path d="M3 3 13 13M13 3 3 13" fill="none" stroke="#E5341D" strokeWidth="2.8" strokeLinecap="square" />
      </svg>
    );
  return (
    <span role="img" aria-label="needs you" className="grid size-[18px] place-items-center rounded-[4px] bg-crash font-mono text-[13px] font-semibold leading-none">
      ?
    </span>
  );
}

type Actions = {
  onRetry: (n: number) => void;
  onDecide: (n: number, d: OwnerDecision) => void;
  onSelect: (n: number) => void;
  /** the retry already run for this test, if any */
  retryN?: number;
};

const btn = "label cursor-pointer rounded-md border-2 border-black px-3.5 py-1 enabled:active:translate-y-px";

/** A printed test sheet. Pure: `shown` is how many rows have printed (6 rows, then the stamp is step 7). */
export function Sheet({ test, shown, animate, actions }: { test: Test | null; shown: number; animate: boolean; actions?: Actions }) {
  const sw = test ? caseOf(test) : null;
  const done = shown >= 7;
  const ask = sw?.verdict === "ask";
  const decision = test?.decision;
  const hidden = !done && "invisible";
  return (
    <div className="relative rounded-md border-2 border-black bg-white font-mono text-[13px] leading-[1.45]">
      <div className="border-b-2 border-black px-3.5 py-2 text-[12px] font-medium sm:text-[13px]">
        {sw && test ? (
          <>
            <span className="font-semibold">TEST {pad(test.n)}</span>
            <span className="text-ink-3"> · </span>
            {test.retryOf !== undefined ? `${LOOP.retryOf} ${pad(test.retryOf)}` : sw.action}
            <span className="text-ink-3"> · </span>
            branch #{test.n}
            <span className="text-ink-3"> · </span>
            {BENCH.duration}
          </>
        ) : (
          <>
            <span className="font-semibold">TEST 000</span>
            <span className="text-ink-3"> · </span>
            waiting for you to flip a switch
          </>
        )}
      </div>
      {sw?.plan ? (
        <p className="border-b border-rule bg-bench/60 px-3.5 py-1.5 text-[12px] leading-[1.4]">
          <span className="text-ink-3">{LOOP.planLabel}: </span>
          {sw.plan}
        </p>
      ) : null}
      <ol>
        {QUESTIONS.map((q, i) => {
          const row = sw?.rows[q.id];
          return (
            <li
              key={q.id}
              className={cn(
                "grid grid-cols-[22px_1fr] gap-x-2.5 gap-y-0.5 border-b border-rule px-3.5 py-[5px] transition-opacity duration-150 sm:grid-cols-[110px_22px_1fr]",
                row && i >= shown ? "opacity-0" : "opacity-100",
              )}
            >
              <span className="order-2 font-medium text-ink sm:order-none">{q.short}</span>
              <span className="order-1 pt-0.5 sm:order-none">
                <MarkGlyph mark={row ? row.mark : "empty"} />
              </span>
              <span className="order-3 col-start-2 min-w-0 sm:order-none sm:col-start-auto">
                {row ? (
                  row.facts.length ? (
                    row.facts.map((f) => (
                      <span key={f.text} className="block">
                        <span className={row.mark === "fail" ? "font-medium text-black" : "text-ink-2"}>{f.text}</span>
                        {f.code ? <span className="block break-all text-[11px] text-ink-3 sm:inline sm:pl-2">{f.code}</span> : null}
                        {f.note ? <span className="block text-[11px] text-ink-3 sm:inline sm:pl-2">{f.note}</span> : null}
                      </span>
                    ))
                  ) : (
                    <span className="text-ink-3">clear</span>
                  )
                ) : null}
              </span>
            </li>
          );
        })}
      </ol>
      <div className={cn("flex flex-col-reverse gap-2 px-3.5 py-2.5 sm:flex-row sm:items-center sm:justify-between sm:gap-6", sw && "min-h-[92px]")}>
        {sw ? (
          <div className={cn("flex max-w-[350px] flex-col items-start gap-2 text-[12px] text-ink-2 transition-opacity duration-150", done ? "opacity-100" : "opacity-0")}>
            {ask && decision ? (
              <p>{OWNER[decision === "approved" ? "approve" : "deny"].line}</p>
            ) : ask ? (
              <p>
                {OWNER.prompt[0]}
                <strong className="font-semibold text-black">{OWNER.prompt[1]}</strong>
                {OWNER.prompt[2]}
              </p>
            ) : (
              <p>{VERDICT[sw.verdict].next}</p>
            )}
            {actions && test ? (
              <div className={cn("flex flex-wrap items-center gap-2", hidden)}>
                {ask && !decision ? (
                  <>
                    <button type="button" onClick={() => actions.onDecide(test.n, "approved")} className={cn(btn, "bg-crash text-black hover:bg-[#f0c800]")}>
                      {OWNER.approve.label}
                    </button>
                    <button type="button" onClick={() => actions.onDecide(test.n, "denied")} className={cn(btn, "bg-white text-black hover:bg-rule")}>
                      {OWNER.deny.label}
                    </button>
                  </>
                ) : null}
                {isRetryable(test) && actions.retryN === undefined ? (
                  <button type="button" onClick={() => actions.onRetry(test.n)} className={cn(btn, "bg-black text-white hover:bg-ink-2")}>
                    {LOOP.retryButton}
                  </button>
                ) : null}
                {isRetryable(test) && actions.retryN !== undefined ? (
                  <button type="button" onClick={() => actions.onSelect(actions.retryN as number)} className="label underline underline-offset-4 hover:text-black">
                    {LOOP.seeRetry(actions.retryN)}
                  </button>
                ) : null}
                {test.retryOf !== undefined ? (
                  <button type="button" onClick={() => actions.onSelect(test.retryOf as number)} className="label underline underline-offset-4 hover:text-black">
                    {LOOP.seeOriginal(test.retryOf)}
                  </button>
                ) : null}
              </div>
            ) : null}
          </div>
        ) : (
          <p className="text-[12px] text-ink-3">flip any switch above to run test 001</p>
        )}
        {sw && done ? (
          <div className="-mt-3 flex flex-col items-end self-end sm:mt-0">
            <div className="relative">
              <Stamp verdict={sw.verdict} animate={animate} />
              {decision ? (
                <DecisionStamp decision={decision} animate={animate} className="absolute -bottom-7 -left-12 z-10 sm:-left-16" />
              ) : null}
            </div>
            {decision === "approved" ? <p className="mt-9 text-[11px] text-ink-3">{OWNER.approve.note}</p> : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}

function Printing({ test }: { test: Test }) {
  const reduced = useReduced();
  const { state, dispatch } = useLab();
  const [shown, setShown] = useState(0);
  useEffect(() => {
    if (reduced) {
      setShown(7);
      return;
    }
    let i = 0;
    const id = setInterval(() => {
      i += 1;
      setShown(i);
      if (i >= 7) clearInterval(id);
    }, 40);
    return () => clearInterval(id);
  }, [reduced]);
  const actions: Actions = {
    onRetry: (n) => dispatch({ type: "retry", of: n }),
    onDecide: (n, decision) => dispatch({ type: "decide", n, decision }),
    onSelect: (n) => dispatch({ type: "select", view: n, reveal: true }),
    retryN: state.tests.find((t) => t.retryOf === test.n)?.n,
  };
  return <Sheet test={test} shown={shown} animate={!reduced} actions={actions} />;
}

/** The latest test, printing row by row. Remounts per test so the print restarts. */
export function Report({ test }: { test: Test | null }) {
  return (
    <div aria-live="polite" aria-label="Test report">
      {test?.retryOf !== undefined ? <p className="mb-2 font-mono text-[12px] text-ink-2">{LOOP.retryAbove}</p> : null}
      {test ? <Printing key={test.n} test={test} /> : <Sheet test={null} shown={0} animate={false} />}
    </div>
  );
}
