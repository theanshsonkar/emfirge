// Agent markdown, generated from the same content that renders the pages. Run by scripts/gen-md.ts before `next build`.
import type { Block, Page } from "./types.ts";
import { PAGES } from "./pages.ts";
import { FIGURE, HERO, LINKS, METRICS, NOTES, RUNS, SITE, TRUST, WHAT, WRITING } from "./site.ts";

const ORIGIN = "https://emfirge.cloud";
// Internal site links become absolute links to the markdown version of the page.
export const abs = (x: string) =>
  x.replace(/\]\((\/[^)#]*)(#[^)]*)?\)/g, (_m, p: string, h?: string) => `](${ORIGIN}${p === "/" ? "/index" : p.replace(/\/$/, "")}.md${h ?? ""})`);

const cell = (x: string) => abs(x).replace(/\|/g, "\\|");

function block(b: Block): string {
  switch (b.t) {
    case "p": return abs(b.x);
    case "lede": return `**${abs(b.x)}**`;
    case "h3": return `### ${b.x}`;
    case "code": return (b.title ? `${b.title}:\n\n` : "") + "```\n" + b.x + "\n```";
    case "table": {
      const head = `| ${b.head.join(" | ")} |\n|${b.head.map(() => "---").join("|")}|`;
      return head + "\n" + b.rows.map((r) => `| ${r.map(cell).join(" | ")} |`).join("\n");
    }
    case "list": return b.items.map((i) => `- ${abs(i)}`).join("\n");
    case "card": return b.parts.map((p) => `${p.label.toUpperCase()}\n` + p.lines.map((l) => `- ${l.x}${l.tag ? ` (${l.tag})` : ""}`).join("\n")).join("\n\n");
    case "note": return `> ${abs(b.x)}`;
    case "fig": return `*${b.caption}*`;
    case "link": return `[${b.label}](${ORIGIN}${b.href.replace(/\/(#|$)/, "$1").replace(/^(\/[^#]*?)(#|$)/, "$1.md$2")})`;
    case "faq": return b.items.map(([q, a]) => `**${q}**\n${abs(a)}`).join("\n\n");
    case "sources": return `Counts from the repository:\n\n| Source | Count |\n|---|---|\n` + METRICS.sources.bars.map((x) => `| ${x.name} | ${x.value} |`).join("\n");
    case "same": return `Same change, same answer (${METRICS.same.law}): ${METRICS.same.rows.join(", ")} all produce the same verdict. ${METRICS.same.foot}`;
    case "setup": return `Open the setup prompt in an agent: Claude (https://claude.ai/new?q=${encodeURIComponent(SETUP_PROMPT)}), ChatGPT (https://chatgpt.com/?q=${encodeURIComponent(SETUP_PROMPT)}), or Cursor.`;
    case "plan": {
      const p = b.plan;
      return `**${p.name}: ${p.price} ${p.unit}.** ${p.blurb}\n\n` + p.includes.map((i) => `- ${i}`).join("\n") + `\n\n${p.foot}`;
    }
    case "entries": return b.items.map((e) => `### ${e.date}: ${e.title} [${e.tag}]\n\n${e.summary}\n\nImprovements:\n${e.improvements.map((i) => `- ${i}`).join("\n")}` + (e.fixes ? `\n\nFixes:\n${e.fixes.map((i) => `- ${i}`).join("\n")}` : "")).join("\n\n");
  }
}
import { SETUP_PROMPT } from "./site.ts";

export function pageMd(p: Page): string {
  const out: string[] = [`# ${p.h1.replace(/\n/g, " ")}`, abs(p.lead), `Human version: ${ORIGIN}${p.href}`];
  for (const b of p.intro ?? []) out.push(block(b));
  for (const s of p.sections) {
    out.push(`## ${s.title}`);
    for (const b of s.blocks) out.push(block(b));
  }
  out.push(footerMd());
  return out.join("\n\n") + "\n";
}

function footerMd() {
  return "---\n\nAll pages as markdown: " + ORIGIN + "/llms.txt. Source: " + LINKS.github + ". Contact: ansh@emfirge.cloud.";
}

export function homeMd(): string {
  const m = METRICS;
  const f = (n: number) => n.toLocaleString("en-US");
  return `# emfirge

${HERO.h1}

${HERO.sub}

- Site: ${ORIGIN}
- Quickstart: ${ORIGIN}/quickstart.md
- How it works: ${ORIGIN}/how-it-works.md
- CLI reference: ${ORIGIN}/cli.md
- Coverage: ${ORIGIN}/coverage.md
- Security & privacy: ${ORIGIN}/security.md
- Pricing: ${ORIGIN}/pricing.md
- Changelog: ${ORIGIN}/changelog.md
- FAQ: ${ORIGIN}/faq.md
- Source: ${LINKS.github}
- Contact: ansh@emfirge.cloud

Works with: ${HERO.worksWith.join(", ")}.

## Mission

The path to agents that run infrastructure isn't a smarter model. It's a true world for them to work in: what exists, what's live, what depends on what, and a safe copy to try a change on before it's real.

Intelligence is no longer the constraint. Trust is.

Agents can already write the Terraform and run the CLI. What they can't do is see what a change will break, and owners can't let them near production without that.

We built the hard parts: a branch engine for your live AWS, six checks that say what a change does to your data, exposure, money, availability, control and the outside world, and a record of what was applied, verified against CloudTrail.

Emfirge supplies the truth. Your agent supplies the intelligence. Emfirge has no AI inside: the same branch always gets the same answer, and it never writes to your cloud.

${FIGURE.caption}

## What we do

${WHAT.rows.map((r) => `- **${r.title}** ${r.text}`).join("\n")}

${WHAT.note}

## In production

Our promise is a world your agent can trust: true facts, unknowns marked honestly, and nothing that ever writes to your cloud.

Numbers, counted from the repository:

| What | Count | How it was counted |
|---|---|---|
| Engine tests (backend) | ${f(m.tests.rows[0].value)} | \`pytest --collect-only\` in backend/ |
| MCP + CLI tests | ${f(m.tests.rows[1].value)} | \`npm test\` in mcp/ |
| Laws | ${m.laws.value} | README, "Built to be trusted" |
| Modeled resource types | ${m.types.value} | \`SUPPORTED_RESOURCE_TYPES\` in backend/app/mutations.py |
| pathfinding.cloud escalation paths | 92 | backend/app/data/pathfinding_paths.json |
| Scanner check reads | 55 | backend/app/data/scanner_check_reads.json |
| Native reason codes | 30 | distinct codes in backend/app/verdict.py |
| Prowler check metadata files | 21 | backend/app/data/third_party/prowler/checks |
| Severity crosswalk entries | 21 | backend/app/data/scanner_severity_crosswalk.json |

Same change, same answer: one rule that opens port 22 to the world gives the same verdict as a typed change, an AWS CLI command, an AWS API call, a Terraform plan or a CloudFormation change set. Law L21 pins Terraform and the AWS API to the same verdict.

> ${NOTES.trust} (Emfirge README)

## Where it runs

${RUNS.title} ${RUNS.text}

${RUNS.cards.map((c, i) => `${i + 1}. ${c.title}`).join("\n")}

## Trust

${TRUST.text}

- Read-only role
- Tokenized IDs
- Open source (AGPL-3.0, Apache-2.0)

Security & privacy: ${ORIGIN}/security.md
Security policy: ${LINKS.securityPolicy}
Privacy: ${LINKS.privacy}

## Writing (${WRITING.tag})

${WRITING.rows.map((r) => `- ${r}`).join("\n")}

---

## How to use emfirge (for agents)

### Install

\`\`\`
npx @emfirge/cli@latest connect
\`\`\`

This signs you in and connects emfirge to the AWS account through a read-only IAM role (one CloudFormation click; delete the stack to revoke). Full steps: ${ORIGIN}/quickstart.md

### The six verbs

1. \`context\`: ask what is true (what exists, what depends on what, the owner's marks in emfirge.md).
2. \`branch\`: open, fork, compare, roll back or discard a copy of the live cloud model. Live never moves.
3. \`try\`: put a change on the branch (AWS CLI command, AWS API call, Terraform plan, CloudFormation change set, or a typed change).
4. \`check\`: six checks answer with facts: data, exposure, money, availability, control, outside world.
5. \`request\`: ask the owner when a check says to.
6. \`report\`: record what you applied, so emfirge can verify it against CloudTrail.

Every flag: ${ORIGIN}/cli.md

### Rules

- Never apply a change that did not pass.
- A block is a fact. Change your plan and retry on a new branch; do not argue with it or route around it.
- Read emfirge.md in the project for the facts about this cloud before proposing changes.
- Emfirge never writes to the cloud. Applying a passing change is your job, with your own credentials.
- Unknown never passes. If a check could not run, the verdict says so.
- Use \`--json\` when you read output. Exit codes: 0 pass, 1 warn or ask, 2 block, 3 error.
`;
}

export function llmsTxt(): string {
  return `# emfirge

> ${SITE.description} Every page below is also served as markdown for agents.

- [Home, with agent instructions](${ORIGIN}/index.md): the whole home page plus "How to use emfirge (for agents)".
${PAGES.map((p) => `- [${p.title}](${ORIGIN}/${p.slug}.md): ${p.description}`).join("\n")}
- [Source](${LINKS.github})
`;
}
