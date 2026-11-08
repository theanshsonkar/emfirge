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
          ["Is it open source?", "The engine is AGPL-3.0, and the MCP adapter and the CLI are Apache-2.0. [Source on GitHub](https://github.com/theanshsonkar/emfirge)."],
          ["What does it cost?", "Nothing while in beta. See [Pricing](/pricing/)."],
        ] },
      ],
    },
    {
      id: "troubleshooting",
      title: "Troubleshooting",
      blocks: [
        { t: "faq", items: [
          ["`emfirge` is not found, or Node errors on start", "Use Node.js 20 or later. `npx emfirge --version` prints the version that runs, and `npx emfirge --help` prints the commands the server offers."],
          ["Access denied or 403 when reading my account", "Check the role ARN, the trusted account and the ExternalId in your stack against the link `emfirge connect` prints; run it again to print the link. A role made with an older shared ExternalId must be redeployed with your own. A 403 is exit code 2."],
          ["The scan is empty", "Confirm the region: most resources are regional and emfirge needs one. Check that the role has the read permissions in [iam-role.yaml](https://github.com/theanshsonkar/emfirge/blob/main/iam-role.yaml). An empty result does not mean your account has no risks."],
          ["Branch not found", "Use the exact ID printed by `emfirge branch list`, against the same backend that created it. This is exit code 3."],
          ["A change was rejected", "The branch must be open, the resource type supported, and the target must exist for a modify or delete. Unknown fields are rejected. Check [Coverage](/coverage/#resources) and run `emfirge try` again with the exact ID."],
          ["HTTP 409 on a change, rollback or discard", "Someone else changed the branch. Run `emfirge branch get` for the new revision token and pass it with `--revision`. This is exit code 5."],
          ["Timeouts or HTTP 429", "A scan can take a while on a large account; the client waits up to 240 seconds. For 429 (exit code 4, `rate_limited`), follow the limit and reset time in the message. The open-branch limit is also a 429: discard branches you no longer need."],
          ["Exit code 6, \"needs a newer emfirge\"", "The server's command is newer than your install. Run `npx emfirge@latest`, then retry."],
          ["`emfirge request` exits 1", "It is not built yet. It prints a JSON error, `not_built`, and sends nothing."],
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
          ["Verb", "One of the six CLI commands: context, branch, try, check, request, report. `request` is not built yet."],
          ["Check", "One of six questions about a branch: data, exposure, money, availability, control, outside world. Each answers with facts, what was checked and what is unknown."],
          ["Unknown", "What a check could not look at, and why. Unknown means not checked. It never means safe."],
          ["Changed setting", "A setting that differs between a branch and its base, named without its value: judged by a check, or named as not judged."],
          ["Verdict", "`pass`, `warn` or `block`, with reasons. Advisory evidence, not a guarantee."],
          ["Reason code", "A stable name for one fact in a verdict, such as `recently_used`."],
          ["Lens", "An evaluator that looks at the branch from one angle. Several lenses feed the six checks."],
          ["Law", "A numbered property test the engine must always satisfy, such as L7: the same snapshot and changes give the same verdict."],
          ["Request", "An ask to the owner, raised by an agent. Not built yet."],
          ["Hand-back", "What `emfirge report` returns: the exact calls, bound by hash to the verdict they were judged with."],
          ["Token", "A stand-in such as `SG_001` for a real identifier, made on your machine."],
          ["emfirge.md", "A planned plain-English file of your marks and limits. Not built yet."],
          ["MCP", "Model Context Protocol: the interface an agent client uses to call tools. Emfirge offers it as an adapter."],
        ] },
      ],
    },
  ],
};
