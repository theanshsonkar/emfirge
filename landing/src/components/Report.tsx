"use client";

import { useEffect, useState } from "react";
import { BENCH, QUESTIONS, VERDICT, type Mark } from "@/content";
import { useReduced } from "@/lib/useReduced";
import { cn } from "@/lib/cn";
import { switchOf, type Test } from "./LabProvider";
import { Stamp } from "./Stamp";

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

/** A printed test sheet. Pure: `shown` is how many rows have printed (6 rows, then the stamp is step 7). */
export function Sheet({ test, shown, animate }: { test: Test | null; shown: number; animate: boolean }) {
  const sw = test ? switchOf(test.switchId) : null;
  const done = shown >= 7;
  return (
    <div className="relative rounded-md border-2 border-black bg-white font-mono text-[13px] leading-[1.45]">
      <div className="border-b-2 border-black px-3.5 py-2.5 text-[12px] font-medium sm:text-[13px]">
        {sw && test ? (
          <>
            <span className="font-semibold">TEST {pad(test.n)}</span>
            <span className="text-ink-3"> · </span>
            {sw.action}
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
      <ol>
        {QUESTIONS.map((q, i) => {
          const row = sw?.rows[q.id];
          return (
            <li
              key={q.id}
              className={cn(
                "grid grid-cols-[22px_1fr] gap-x-2.5 gap-y-0.5 border-b border-rule px-3.5 py-2 transition-opacity duration-150 sm:grid-cols-[110px_22px_1fr]",
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
                        {f.note ? <span className="block text-[11px] text-ink-3">{f.note}</span> : null}
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
      <div className={cn("flex flex-col-reverse gap-2 px-3.5 py-3 sm:flex-row sm:items-center sm:justify-between sm:gap-6", sw && "min-h-[96px]")}>
        <p className={cn("max-w-[340px] text-[12px] text-ink-2 transition-opacity duration-150", done ? "opacity-100" : "opacity-0", !sw && "hidden")}>
          {sw ? VERDICT[sw.verdict].next : ""}
        </p>
        {!sw ? <p className="text-[12px] text-ink-3">flip any switch above to run test 001</p> : null}
        {sw && done ? <Stamp verdict={sw.verdict} animate={animate} className="-mt-3 self-end sm:mt-0" /> : null}
      </div>
    </div>
  );
}

function Printing({ test }: { test: Test }) {
  const reduced = useReduced();
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
  return <Sheet test={test} shown={shown} animate={!reduced} />;
}

/** The latest test, printing row by row. Remounts per test so the print restarts. */
export function Report({ test }: { test: Test | null }) {
  return (
    <div aria-live="polite" aria-label="Test report">
      {test ? <Printing key={test.n} test={test} /> : <Sheet test={null} shown={0} animate={false} />}
    </div>
  );
}
