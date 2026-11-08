import type { Page } from "./types.ts";

export const faq: Page = {
  slug: "faq",
  href: "/faq/",
  nav: "FAQ",
  title: "FAQ",
  h1: "FAQ.\nQuestions, fixes and terms.",
  lead: "Short answers, what to do when something fails, and the words emfirge uses.",
  description: "Common questions about emfirge, troubleshooting for the CLI, and a glossary.",
  sections: [
    {
      id: "questions",
      title: "Questions",
      blocks: [
        { t: "faq", items: [
          ["Does emfirge change my AWS?", "No. It is read-only. Your agent applies with its own credentials; emfirge records and verifies."],
          ["Which agents work?", "Any agent that can run a shell command: Claude Code, Codex, Cursor, Gemini CLI and others. An MCP adapter covers clients that cannot."],
          ["Which clouds?", "AWS today. The core is built to be cloud-neutral, with one adapter per cloud, but only AWS exists."],
          ["Does my data go to an LLM?", "Emfirge has no LLM. Identifiers are tokenized on your machine before your agent's model sees them. See [Security & privacy](/security/)."],
          ["Is a pass a guarantee?", "No. A branch is a model of your cloud. A pass is evidence, and every verdict says what was checked and what was not."],
          ["What if emfirge cannot model my change?", "It cannot pass. The change is listed as unmodeled and the verdict gets stricter. See [Coverage](/coverage/)."],
          ["Does a block stop my agent?", "Only if the agent listens. Emfirge is advisory today: it does not stop anyone with their own AWS credentials."],
          ["Is it open source?", "The engine is AGPL-3.0 and the MCP adapter is Apache-2.0. [Source on GitHub](https://github.com/theanshsonkar/emfirge)."],
          ["What does it cost?", "Nothing while in beta. See [Pricing](/pricing/)."],
        ] },
      ],
    },
    {
      id: "troubleshooting",
      title: "Troubleshooting",
      blocks: [
        { t: "faq", items: [
          ["`emfirge` is not found, or Node errors on start", "Use Node.js 20 or later. Run `npx @emfirge/cli@latest status` to see what is installed and which backend it talks to."],
          ["Access denied or 403 when reading my account", "Run `emfirge status` and check the role ARN, the trusted account and the ExternalId in the stack. Re-run `emfirge connect` to print the setup link again."],
          ["The scan is empty", "Confirm the region: most resources are regional and emfirge needs one. Check that the role has the read permissions in [iam-role.yaml](https://github.com/theanshsonkar/emfirge/blob/main/iam-role.yaml). An empty result does not mean your account has no risks."],
          ["Branch not found", "Use the exact name or ID printed by `emfirge branch list`, against the same backend that created it."],
          ["A change was rejected", "The branch must be open, the resource type supported, and the target must exist for a modify or delete. Unknown fields are rejected. Check [Coverage](/coverage/#resources) and run `emfirge try` again with the exact ID."],
          ["HTTP 409 on a change, rollback or discard", "Someone else changed the branch. Run `emfirge branch show` for the new revision token and pass it with `--revision`."],
          ["Timeouts or HTTP 429", "A scan can take a while on a large account; the client waits up to 240 seconds. For 429, follow the limit and reset time in the message."],
          ["The verdict says a scanner was unavailable", "Native results still return. `coverage_warnings` says the result is not full coverage. Do not treat it as complete."],
        ] },
      ],
    },
    {
      id: "glossary",
      title: "Glossary",
      blocks: [
        { t: "table", head: ["Term", "Meaning"], key: true, rows: [
          ["Branch", "A base snapshot plus an ordered list of changes. An empty branch equals live."],
          ["Snapshot", "What emfirge read from your account at one moment. The base of every branch."],
          ["Change", "One add, modify or delete of a supported resource on a branch."],
          ["Context", "What is true about your cloud: what exists, what is live, what depends on what, and your marks."],
          ["Verb", "One of the six CLI commands: context, branch, try, check, request, report."],
          ["Check", "One of six questions about a branch: data, exposure, money, availability, control, outside world."],
          ["Verdict", "`pass`, `warn` or `block`, with reasons. Advisory evidence, not a guarantee."],
          ["Reason code", "A stable name for one fact in a verdict, such as `recently_used`."],
          ["Lens", "An evaluator that looks at the branch from one angle. Several lenses feed the six checks."],
          ["Law", "A numbered property test the engine must always satisfy, such as L7: the same snapshot and changes give the same verdict."],
          ["Tell and ask", "The two responses to a fact: write it in the record, or stop for the owner."],
          ["Request", "An ask to the owner, raised by an agent."],
          ["Report", "The agent's record of what it applied, bound by hash to the verdict it passed."],
          ["Token", "A stand-in such as `SG_001` for a real identifier, made on your machine."],
          ["emfirge.md", "A plain-English file of your marks and limits that agents read as context."],
          ["MCP", "Model Context Protocol: the interface an agent client uses to call tools. Emfirge offers it as an adapter."],
        ] },
      ],
    },
  ],
};
