"use client";

import { useState } from "react";
import { LAB, LIVE_BAR, VERDICT, type Verdict } from "@/content";
import { cn } from "@/lib/cn";
import { CopyCommand } from "./CopyCommand";
import { caseOf, isRetryable, useLab, type Test } from "./LabProvider";

const pad = (n: number) => String(n).padStart(3, "0");
const CHIP: Record<Verdict, string> = {
  blocked: "bg-block text-white",
  ask: "bg-crash text-black",
  passed: "bg-pass text-white",
};
const SESSION_CHARS = "abcdefghjkmnpqrstuvwxyz23456789";
const makeSession = () =>
  Array.from({ length: 4 }, () => SESSION_CHARS[Math.floor(Math.random() * SESSION_CHARS.length)]).join("");

/** Copy to the clipboard; falls back to a hidden textarea where the async API is blocked. */
async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      ta.remove();
      return ok;
    } catch {
      return false;
    }
  }
}

function note(t: Test, tests: Test[]): string {
  if (t.retryOf === undefined && isRetryable(t) && tests.some((x) => x.retryOf === t.n)) return LAB.notes.fixed;
  if (t.decision) return LAB.notes[t.decision];
  return "";
}

/** The payoff: appears under the bench once all 7 switches have been thrown. Reads the reducer, nothing else. */
export function LabReport() {
  const { state, counts, complete } = useLab();
  const [session] = useState(makeSession);
  const [copied, setCopied] = useState(false);
  if (!complete) return null;

  const summary = LAB.text(counts);
  async function copy() {
    if (await copyText(summary)) {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    }
  }

  return (
    <section id="lab-report" aria-labelledby="lab-h" className="lab-in mt-5 scroll-mt-14 rounded-md border-2 border-black bg-white font-mono text-[13px]">
      <h3 id="lab-h" className="border-b-2 border-black px-3.5 py-2 text-[12px] font-medium sm:text-[13px]">
        <span className="font-semibold">{LAB.title}</span>
        <span className="text-ink-3"> · </span>session {session}
        <span className="text-ink-3"> · </span>
        {counts.total} tests
        {counts.retries ? <span className="text-ink-3"> · {counts.retries} {counts.retries === 1 ? "retry" : "retries"}</span> : null}
      </h3>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left">
          <caption className="sr-only">One row per test run this session</caption>
          <thead className="sr-only">
            <tr>
              <th>test</th>
              <th>action</th>
              <th>stamp</th>
              <th>note</th>
            </tr>
          </thead>
          <tbody>
            {state.tests.map((t) => {
              const c = caseOf(t);
              const n = note(t, state.tests);
              return (
                <tr key={t.n} className="border-b border-rule">
                  <td className="whitespace-nowrap py-[5px] pl-3.5 pr-3 text-ink-3">{pad(t.n)}</td>
                  <td className="py-[5px] pr-3">
                    {t.retryOf !== undefined ? <span className="text-ink-3">retry · </span> : null}
                    {c.action}
                  </td>
                  <td className="py-[5px] pr-3">
                    <span className={cn("inline-block rounded-[3px] px-1.5 py-px text-[10.5px] font-semibold leading-[1.5] tracking-[0.02em]", CHIP[c.verdict])}>
                      {VERDICT[c.verdict].stamp}
                    </span>
                  </td>
                  <td className="py-[5px] pr-3.5 text-[12px] text-ink-2 sm:whitespace-nowrap">{n}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <div className="px-3.5 pb-4 pt-4">
        <p className="display font-sans text-[26px] sm:text-[32px]">{LAB.summaryLine(counts.total)}</p>
        <p className="mb-2.5 mt-5 text-[12px] text-ink-2">{LAB.give}</p>
        <div className="flex flex-wrap items-stretch gap-3">
          <div className="min-w-0 max-w-full">
            <CopyCommand />
          </div>
          <a
            href={LIVE_BAR.cta.href}
            className="label grid place-items-center rounded-md bg-black px-4 text-white hover:bg-ink-2"
          >
            {LIVE_BAR.cta.label}
          </a>
        </div>
        <div className="mt-5 flex flex-wrap items-start gap-3">
          <button
            type="button"
            onClick={copy}
            className="label cursor-pointer rounded-md border-2 border-black bg-crash px-3.5 py-1.5 hover:bg-[#f0c800]"
          >
            {copied ? LAB.copied : LAB.copy}
          </button>
          <pre className="min-w-0 max-w-full flex-1 select-all whitespace-pre-wrap break-words rounded-md border border-rule bg-bench/60 px-3 py-1.5 text-[12px] leading-[1.5] text-ink-2">{summary}</pre>
        </div>
        <span className="sr-only" role="status" aria-live="polite">
          {copied ? "Summary copied to clipboard" : ""}
        </span>
      </div>
    </section>
  );
}

