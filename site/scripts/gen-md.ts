// Writes public/<page>.md, public/index.md and public/llms.txt from src/content. Runs before `next build`.
import { mkdirSync, writeFileSync } from "node:fs";
import { PAGES } from "../src/content/pages.ts";
import { homeMd, llmsTxt, pageMd } from "../src/content/markdown.ts";

mkdirSync("public", { recursive: true });
writeFileSync("public/index.md", homeMd());
for (const p of PAGES) writeFileSync(`public/${p.slug}.md`, pageMd(p));
writeFileSync("public/llms.txt", llmsTxt());
console.log(`wrote ${PAGES.length + 1} markdown pages and llms.txt`);
