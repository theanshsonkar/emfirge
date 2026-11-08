"use client";
import { useSyncExternalStore } from "react";
import { TODOS } from "@/content/site";

// Open unknowns are for Ansh, not for visitors. They show only with ?todo=1 in the URL (or in `next dev`).
// The server HTML and the .md files never contain them: the server snapshot is always "off".
const subscribe = () => () => {};
const snap = () => process.env.NODE_ENV === "development" || new URLSearchParams(window.location.search).get("todo") === "1";
export const useTodoMode = () => useSyncExternalStore(subscribe, snap, () => false);

export function TodoMark({ text }: { text: string }) {
  return useTodoMode() ? <mark className="todo">{text}</mark> : null;
}

export function TodoList({ page }: { page: string }) {
  const on = useTodoMode();
  const items = TODOS.filter((t) => t.page === page);
  if (!on || !items.length) return null;
  return (
    <aside className="todo-list" aria-label="Open TODOs">
      <div className="label">Open TODOs for this page</div>
      <ul>{items.map((t) => <li key={t.text}><mark className="todo">[TODO Ansh: {t.text}]</mark></li>)}</ul>
    </aside>
  );
}
