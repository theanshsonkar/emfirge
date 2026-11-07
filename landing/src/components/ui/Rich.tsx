import { Fragment } from "react";

/** Renders `code` and *emphasis* from a plain string. */
export function Rich({ text }: { text: string }) {
  const parts = text.split(/(`[^`]+`|\*[^*]+\*)/g);
  return (
    <>
      {parts.map((p, i) => {
        if (p.startsWith("`")) return <code key={i} className="font-mono text-[0.9em] text-paper">{p.slice(1, -1)}</code>;
        if (p.startsWith("*")) return <em key={i}>{p.slice(1, -1)}</em>;
        return <Fragment key={i}>{p}</Fragment>;
      })}
    </>
  );
}
