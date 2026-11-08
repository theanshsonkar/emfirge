"use client";

import { createContext, useContext, useMemo, useReducer, type ReactNode } from "react";
import {
  RETRIES,
  SWITCHES,
  type Damage,
  type NodeId,
  type OwnerDecision,
  type QuestionId,
  type Row,
  type Verdict,
} from "@/content";

/** One run on one branch. `retryOf` marks a follow-up with the agent's corrected plan. */
export type Test = { n: number; switchId: number; retryOf?: number; decision?: OwnerDecision };
export type View = "live" | number;
/** The single source of truth. The bench, the live bar, the transcript and the lab report all read this. */
export type LabState = { tests: Test[]; selected: View; /** bumps when the bench should scroll into view */ seq: number };
type Action =
  | { type: "run"; switchId: number }
  | { type: "retry"; of: number }
  | { type: "decide"; n: number; decision: OwnerDecision }
  | { type: "select"; view: View; reveal?: boolean }
  | { type: "reset" };

const initial: LabState = { tests: [], selected: "live", seq: 0 };

export function switchOf(id: number) {
  return SWITCHES.find((s) => s.id === id) ?? SWITCHES[0];
}

/** What a test shows: a switch's own result, or the retry's corrected plan. */
export type Case = {
  action: string;
  target: NodeId;
  verdict: Verdict;
  rows: Record<QuestionId, Row>;
  damage: Damage;
  commands: string[];
  plan?: string;
};

export function caseOf(t: Test): Case {
  const sw = switchOf(t.switchId);
  if (t.retryOf !== undefined) {
    const r = RETRIES.find((x) => x.switchId === t.switchId) ?? RETRIES[0];
    return { action: r.action, target: r.target, verdict: "passed", rows: r.rows, damage: r.damage, commands: r.commands, plan: r.plan };
  }
  return sw;
}

export const isRetryable = (t: Test) =>
  t.retryOf === undefined && switchOf(t.switchId).verdict === "blocked" && RETRIES.some((r) => r.switchId === t.switchId);

function reducer(state: LabState, action: Action): LabState {
  switch (action.type) {
    case "run": {
      if (state.tests.some((t) => t.switchId === action.switchId && t.retryOf === undefined)) return state;
      const n = state.tests.length + 1;
      return { tests: [...state.tests, { n, switchId: action.switchId }], selected: n, seq: state.seq + 1 };
    }
    case "retry": {
      const from = state.tests.find((t) => t.n === action.of);
      if (!from || !isRetryable(from) || state.tests.some((t) => t.retryOf === from.n)) return state;
      const n = state.tests.length + 1;
      return { tests: [...state.tests, { n, switchId: from.switchId, retryOf: from.n }], selected: n, seq: state.seq + 1 };
    }
    case "decide":
      return {
        ...state,
        tests: state.tests.map((t) =>
          t.n === action.n && !t.decision && caseOf(t).verdict === "ask" ? { ...t, decision: action.decision } : t,
        ),
        seq: state.seq + 1,
      };
    case "select":
      return { ...state, selected: action.view, seq: action.reveal ? state.seq + 1 : state.seq };
    case "reset":
      return initial;
  }
}

export type Counts = { total: number; blocked: number; asked: number; passed: number; retries: number };

type Lab = {
  state: LabState;
  dispatch: (a: Action) => void;
  /** tries Emfirge caught: BLOCKED or ASK OWNER (a decided ask still counts) */
  caught: number;
  /** the test the report is showing: the selected branch, else the latest */
  shown: Test | null;
  /** counts over the switches thrown (retries counted apart) */
  counts: Counts;
  /** all 7 switches have been thrown: the lab report is earned */
  complete: boolean;
};

const Ctx = createContext<Lab | null>(null);

export function LabProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initial);
  const value = useMemo<Lab>(() => {
    const caught = state.tests.filter((t) => caseOf(t).verdict !== "passed").length;
    const shown =
      state.selected === "live"
        ? (state.tests[state.tests.length - 1] ?? null)
        : (state.tests.find((t) => t.n === state.selected) ?? null);
    const originals = state.tests.filter((t) => t.retryOf === undefined);
    const by = (v: Verdict) => originals.filter((t) => switchOf(t.switchId).verdict === v).length;
    const counts: Counts = {
      total: originals.length,
      blocked: by("blocked"),
      asked: by("ask"),
      passed: by("passed"),
      retries: state.tests.length - originals.length,
    };
    return { state, dispatch, caught, shown, counts, complete: originals.length === SWITCHES.length };
  }, [state]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useLab(): Lab {
  const v = useContext(Ctx);
  if (!v) throw new Error("useLab outside LabProvider");
  return v;
}

