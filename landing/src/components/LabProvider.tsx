"use client";

import { createContext, useContext, useMemo, useReducer, type ReactNode } from "react";
import { SWITCHES, type SwitchDef } from "@/content";

export type Test = { n: number; switchId: number };
export type View = "live" | number;
export type LabState = { tests: Test[]; selected: View };
type Action = { type: "run"; switchId: number } | { type: "select"; view: View } | { type: "reset" };

const initial: LabState = { tests: [], selected: "live" };

function reducer(state: LabState, action: Action): LabState {
  switch (action.type) {
    case "run": {
      if (state.tests.some((t) => t.switchId === action.switchId)) return state;
      const n = state.tests.length + 1;
      return { tests: [...state.tests, { n, switchId: action.switchId }], selected: n };
    }
    case "select":
      return { ...state, selected: action.view };
    case "reset":
      return initial;
  }
}

export function switchOf(id: number): SwitchDef {
  return SWITCHES.find((s) => s.id === id) ?? SWITCHES[0];
}

type Lab = {
  state: LabState;
  dispatch: (a: Action) => void;
  caught: number;
  /** the test the report is showing: the selected branch, else the latest */
  shown: Test | null;
};

const Ctx = createContext<Lab | null>(null);

export function LabProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initial);
  const value = useMemo<Lab>(() => {
    const caught = state.tests.filter((t) => switchOf(t.switchId).verdict !== "passed").length;
    const shown =
      state.selected === "live"
        ? (state.tests[state.tests.length - 1] ?? null)
        : (state.tests.find((t) => t.n === state.selected) ?? null);
    return { state, dispatch, caught, shown };
  }, [state]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useLab(): Lab {
  const v = useContext(Ctx);
  if (!v) throw new Error("useLab outside LabProvider");
  return v;
}
