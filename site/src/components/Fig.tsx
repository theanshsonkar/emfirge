"use client";
import dynamic from "next/dynamic";
import type { Block } from "@/content/types";

// Each figure is its own chunk, so a page only loads the figure it shows.
const FIGS = {
  steps: dynamic(() => import("@/graphics/Steps")),
  loop: dynamic(() => import("@/graphics/Figure1").then((m) => m.Figure1)),
  branch: dynamic(() => import("@/graphics/BranchFig")),
  ways: dynamic(() => import("@/graphics/WaysFig")),
  checks: dynamic(() => import("@/graphics/ChecksFig")),
  record: dynamic(() => import("@/graphics/RecordFig")),
  verbmap: dynamic(() => import("@/graphics/VerbMap")),
  coverage: dynamic(() => import("@/graphics/CoverageFig")),
  role: dynamic(() => import("@/graphics/RoleFig")),
  token: dynamic(() => import("@/graphics/TokenFig")),
};

export function Fig({ id, caption }: { id: Extract<Block, { t: "fig" }>["id"]; caption: string }) {
  const C = FIGS[id];
  return (
    <figure className={`fig fig-${id}`} data-reveal>
      <div className={`fig-frame fr-${id}`}><C /></div>
      <figcaption className="cap">{caption}</figcaption>
    </figure>
  );
}
