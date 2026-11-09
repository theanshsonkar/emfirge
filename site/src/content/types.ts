// Typed page content for the v7 inner pages. One file per page in this folder.
// Inline text uses plain Markdown: `code`, **bold**, [label](href). Internal hrefs are site paths ("/cli/#try").
// Open unknowns are not written into page text. They live in TODOS (site.ts) and show only with ?todo=1. A stray
// [TODO Ansh: ...] token in a string is stripped from the markdown and rendered only with ?todo=1.
// The same data renders the HTML page (components/Blocks.tsx) and the agent markdown (markdown.ts).

export type Line = { x: string; tag?: string };
export type Entry = { date: string; iso: string; tag: string; title: string; summary: string; improvements: string[]; fixes?: string[] };
export type Plan = { name: string; price: string; unit: string; blurb: string; includes: string[]; cta: { label: string; href: string }; foot: string };

export type Block =
  | { t: "p"; x: string }
  | { t: "lede"; x: string }
  | { t: "h3"; x: string }
  | { t: "code"; title?: string; x: string }
  | { t: "table"; head: string[]; rows: string[][]; mono?: number[]; key?: boolean; ops?: number[] }
  | { t: "list"; items: string[] }
  | { t: "card"; parts: { label: string; lines: Line[] }[] }
  | { t: "note"; x: string }
  | { t: "fig"; id: "steps" | "loop" | "branch" | "ways" | "checks" | "record" | "verbmap" | "coverage" | "role" | "token"; caption: string }
  | { t: "link"; label: string; href: string }
  | { t: "faq"; items: [string, string][] }
  | { t: "sources" }
  | { t: "same" }
  | { t: "setup" }
  | { t: "details"; summary: string; blocks: Block[] }
  | { t: "plan"; plan: Plan }
  | { t: "entries"; items: Entry[] };

export type Section = { id: string; title: string; blocks: Block[] };
export type Page = {
  slug: string; // "" for home
  href: string; // "/quickstart/"
  nav: string;
  title: string; // browser title
  h1: string; // may contain \n
  lead: string;
  description: string;
  intro?: Block[];
  sections: Section[];
};
