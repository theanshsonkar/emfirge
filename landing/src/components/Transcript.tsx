"use client";

import { TRANSCRIPT } from "@/content";
import { switchOf, useLab } from "./LabProvider";

/** The CLI transcript for the last test the visitor ran (or test 1). */
export function Transcript() {
  const { state } = useLab();
  const last = state.tests[state.tests.length - 1];
  const sw = switchOf(last ? last.switchId : 1);
  return (
    <section id="how" aria-labelledby="how-h" className="mx-auto max-w-[1320px] px-4 py-16 sm:px-8 lg:py-24">
      <h2 id="how-h" className="display text-[32px] sm:text-[40px]">
        {TRANSCRIPT.title}
      </h2>
      <div className="mt-10 grid grid-cols-[minmax(0,1fr)] gap-10 lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)] lg:gap-16">
        <div>
          <pre className="overflow-x-auto rounded-md bg-black p-5 font-mono text-[14px] leading-[1.7] text-white" aria-label="Terminal transcript">
            {sw.commands.map((c, i) => (
              <span key={i} className={c.startsWith("  ") ? "block font-semibold text-crash" : "block"}>
                {c}
              </span>
            ))}
          </pre>
          <p className="mt-2.5 font-mono text-[12px] text-ink-3">{last ? `branch #${last.n} · ${TRANSCRIPT.captionTest}` : TRANSCRIPT.captionExample}</p>
        </div>
        <div>
          <ol className="space-y-5">
            {TRANSCRIPT.steps.map((s) => (
              <li key={s.n} className="flex gap-4">
                <span className="mt-0.5 grid size-7 shrink-0 place-items-center rounded-full border-2 border-black font-mono text-[13px] font-semibold">
                  {s.n}
                </span>
                <span>
                  <span className="font-bold">{s.name}:</span> {s.text}
                </span>
              </li>
            ))}
          </ol>
          <p className="mt-8 max-w-[30em] text-[15px] text-ink-2">{TRANSCRIPT.agents}</p>
        </div>
      </div>
    </section>
  );
}
