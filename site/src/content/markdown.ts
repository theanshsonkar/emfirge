// Agent markdown, generated from the same content that renders the pages. Run by scripts/gen-md.ts before `next build`.
import type { Block, Page } from "./types.ts";
import { PAGES } from "./pages.ts";
import { FIGURE, HERO, LINKS, METRICS, NOTES, RUNS, SITE, TRUST, WHAT, WRITING } from "./site.ts";

const ORIGIN = "https://emfirge.cloud";
// Internal site links become absolute links to the markdown version of the page.
// A link to a file that already has an extension (/cli.md, /llms.txt) only gets the origin.
export const abs = (x: string) =>
  x.replace(/\]\((\/[^)#]*)(#[^)]*)?\)/g, (_m, p: string, h?: string) =>
    /\.(md|txt)$/.test(p) ? `](${ORIGIN}${p}${h ?? ""})` : `](${ORIGIN}${p === "/" ? "/index" : p.replace(/\/$/, "")}.md${h ?? ""})`);

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
    case "same": return `Same change, same answer: ${METRICS.same.rows.map((r) => `${r.name} (${r.law ?? r.note})`).join(", ")} all produce the same verdict. ${METRICS.same.foot}`;
    case "setup": return `Open the setup prompt in an agent: Claude (https://claude.ai/new?q=${encodeURIComponent(SETUP_PROMPT)}), ChatGPT (https://chatgpt.com/?q=${encodeURIComponent(SETUP_PROMPT)}), or Cursor.`;
    case "details": return `### ${b.summary}\n\n` + b.blocks.map(block).join("\n\n");
    case "plan": {
      const p = b.plan;
      return `**${p.name}: ${p.price} ${p.unit}.** ${p.blurb}\n\n` + p.includes.map((i) => `- ${i}`).join("\n") + `\n\n${p.foot}`;
    }
    case "entries": return b.items.map((e) => `### ${e.date}: ${e.title} [${e.tag}]\n\n${e.summary}\n\nImprovements:\n${e.improvements.map((i) => `- ${i}`).join("\n")}` + (e.fixes ? `\n\nFixes:\n${e.fixes.map((i) => `- ${i}`).join("\n")}` : "")).join("\n\n");
  }
}
import { SETUP_PROMPT } from "./site.ts";
import { cli } from "./cli.ts";

// Open unknowns never reach the agent files: they live in TODOS (site.ts) and show only on the site with ?todo=1.
const noTodo = (s: string) => s.replace(/ ?\[TODO Ansh:[^\]]*\]/g, "");

export function pageMd(p: Page): string {
  const out: string[] = [`# ${p.h1.replace(/\n/g, " ")}`, abs(p.lead), `Human version: ${ORIGIN}${p.href}`];
  for (const b of p.intro ?? []) out.push(block(b));
  for (const s of p.sections) {
    out.push(`## ${s.title}`);
    for (const b of s.blocks) out.push(block(b));
  }
  out.push(footerMd());
  return noTodo(out.join("\n\n") + "\n");
}

function footerMd() {
  return "---\n\nAll pages as markdown: " + ORIGIN + "/llms.txt. Source: " + LINKS.github + ". Contact: ansh@emfirge.cloud.";
}

export function homeMd(): string {
  return noTodo(homeMdRaw());
}

function homeMdRaw(): string {
  const m = METRICS;
  const f = (n: number) => n.toLocaleString("en-US");
  return `# emfirge

${HERO.h1}

${HERO.sub}

## Give emfirge to your agent

People don't use the emfirge CLI; their AI agent does. A person sets it up once (paste the prompt below into the agent, approve the browser sign-in, create the read-only AWS role with one click and give the agent its ARN). The agent does the rest: it opens a branch, tries a change, checks it, fixes its own plan and hands back.

\`\`\`
${SETUP_PROMPT}
\`\`\`

For you (the person):

- Site: ${ORIGIN}
- Set up: ${ORIGIN}/quickstart.md
- How it works: ${ORIGIN}/how-it-works.md
- Coverage: ${ORIGIN}/coverage.md
- Security & privacy: ${ORIGIN}/security.md
- Pricing: ${ORIGIN}/pricing.md
- Changelog: ${ORIGIN}/changelog.md
- FAQ: ${ORIGIN}/faq.md

For your agent:

- CLI reference: ${ORIGIN}/cli.md
- All pages as markdown: ${ORIGIN}/llms.txt
- Source: ${LINKS.github}
- Contact: ansh@emfirge.cloud

Works with: ${HERO.worksWith.join(", ")}.

## Mission

The path to agents that run infrastructure isn't a smarter model. It's a true world for them to work in: what exists, what's live, what depends on what, and a safe copy to try a change on before it's real.

Intelligence is no longer the constraint. Trust is.

Agents can already write the Terraform and run the CLI. What they can't do is see what a change will break, and owners can't let them near production without that.

We built the hard parts: a branch engine for your live AWS, six checks that say what a change does to your data, exposure, money, availability, control and the outside world, and a record of what was applied, bound by hash to the verdict it was judged with.

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
| Laws | ${m.laws.value} | distinct L1 to L88 ids in the tests |
| Modeled resource types | ${m.types.value} | \`SUPPORTED_RESOURCE_TYPES\` in backend/app/mutations.py |
| pathfinding.cloud escalation paths | 92 | backend/app/data/pathfinding_paths.json |
| Scanner check reads | 55 | backend/app/data/scanner_check_reads.json |
| Native reason codes | 32 | distinct codes in backend/app/verdict.py |
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

### Set up (you run the commands; your human approves two things)

\`\`\`
npx -y emfirge login
npx -y emfirge connect
npx -y emfirge context --refresh --role-arn ARN --region REGION
npx -y emfirge context inventory
\`\`\`

- \`login\` opens your human's browser to sign in with GitHub or Google (a page on 127.0.0.1 of the machine you run on; it waits 5 minutes). Your human must approve it; if the browser does not open, show them the address it prints, then wait. It is kept in ~/.emfirge/credentials.json, so you need them again only if it expires.
- \`connect\` prints a one-click CloudFormation link that creates a read-only IAM role (delete the stack to revoke). Show the link to your human. They create the stack, copy the RoleArn from its Outputs and give it to you. \`connect\` takes no ARN. Ask which AWS region to use; there is no default. Keep the ARN: \`check --evidence\` needs it again.
- After that you can do everything yourself. Node.js 20 or later. Human steps: ${ORIGIN}/quickstart.md

### The verbs

1. \`context\`: ask what is true (\`emfirge context inventory\`; 11 questions: inventory, resource, depends_on, dependents, reachable, access, data, cost, live, marks, baseline).
2. \`branch\`: \`open\`, \`fork\`, \`list\`, \`get\`, \`rollback\`, \`rollback-to\`, \`discard\`, \`compare\` a copy of the live cloud model. Live never moves.
3. \`try\`: put a change on the branch (\`--typed\`, \`--aws-cli\`, \`--aws-api\`, \`--terraform\`, \`--cloudformation\`).
4. \`check\`: six answers with facts, what was checked and what is unknown: data, exposure, money, availability, control, outside world. Plus \`changed_settings\`. \`--verdict\` gives pass, warn or block.
5. \`request\`: ask the owner. Not built yet: it exits 1.
6. \`report\`: the hand-back of what you applied, bound by hash to the verdict (\`--verify\` checks the binding).

Every flag: ${ORIGIN}/cli.md. Run \`emfirge guide\` for the agent guide. When a change passes, apply it yourself, run \`emfirge report BRANCH\`, and tell your human what changed.

### Rules

- Emfirge never writes to the cloud. You apply your own change, with your own access.
- Facts, not fixes. Emfirge will not tell you what to do.
- Unknown means not checked. It never means safe. Read every \`unknown\` entry and every changed setting that is not judged.
- Names and IDs come back as tokens (\`S3_001\`, \`NAME_003\`, \`TAG_001\`). Pass them back as they are.
- Emfirge keeps no plan text, only its SHA-256. Apply your own original plan.
- Never apply a change that did not pass. Emfirge is advisory and stops nothing, so this is on you.
- Run \`check --policy\` and \`check --evidence\` (they show an estimate first) only after your human agrees.
- Output is JSON on stdout (\`--human\` for short text); errors are JSON on stderr. Exit codes: 0 ok, 1 usage or rejected input, 2 not signed in, 3 not found, 4 server error or rate limit, 5 conflict, 6 needs a newer emfirge (run \`npx emfirge@latest\`). A finding never changes the exit code.
`;
}

export function llmsTxt(): string {
  return noTodo(`# emfirge

> ${SITE.description} People don't use the CLI; their AI agent does. A person sets it up once, then the agent runs it. Every page below is also served as markdown for agents.

If your human asked you to set up emfirge, read the CLI reference and follow "Setup, loop and rules".

For your agent:

- [CLI reference (agent reference)](${ORIGIN}/cli.md): ${cli.description}
- [Home, with agent instructions](${ORIGIN}/index.md): the whole home page plus "How to use emfirge (for agents)".
- [Source](${LINKS.github})

For your human:

${PAGES.filter((p) => p.slug !== "cli").map((p) => `- [${p.title}](${ORIGIN}/${p.slug}.md): ${p.description}`).join("\n")}
`);
}
