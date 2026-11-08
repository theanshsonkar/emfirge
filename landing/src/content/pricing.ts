import type { Page } from "./types.ts";

export const pricing: Page = {
  slug: "pricing",
  href: "/pricing/",
  nav: "Pricing",
  title: "Pricing",
  h1: "Free while in beta.\nOne plan, everything included.",
  lead: "Emfirge is in beta and costs nothing to use. This page says what is included, what can still cost you money on AWS, and what we have not decided yet.",
  description: "Emfirge is free while in beta: what is included, what can cost money on your AWS bill, and what happens after beta.",
  sections: [
    {
      id: "plan",
      title: "The plan",
      blocks: [
        { t: "plan", plan: {
          name: "Beta",
          price: "Free",
          unit: "while in beta",
          blurb: "For anyone letting an agent change AWS.",
          includes: [
            "The verbs that are built: context, branch, try, check and report (`request` is not built yet)",
            "The CLI and the MCP adapter",
            "The hosted engine, with the six checks on every branch",
            "The read-only role, revocable by deleting one stack",
            "Support by email: ansh@emfirge.cloud",
            "[TODO Ansh: confirm the beta limits the production server sets. The engine's code defaults are 5 scans per AWS account per day, 30 branch requests per minute and 10 open branches per base scan.]",
          ],
          cta: { label: "Get started", href: "/quickstart/" },
          foot: "The engine is open source (AGPL-3.0). Self-hosting is possible but unsupported.",
        } },
      ],
    },
    {
      id: "after-beta",
      title: "What happens after beta",
      blocks: [
        { t: "p", x: "[TODO Ansh: post-beta pricing, whether a free tier stays for one account, and how much notice beta users get. Nothing has been decided, so none of it is promised here.]" },
      ],
    },
    {
      id: "costs",
      title: "Questions",
      blocks: [
        { t: "faq", items: [
          ["Does emfirge cost money while in beta?", "No. There is no charge for the CLI, the engine or the checks."],
          ["Will emfirge add to my AWS bill?", "Two opt-in features can cost you: AWS IAM Access Analyzer policy checks (about $0.002 a policy, billed to your AWS account) and usage evidence reads from CloudTrail and CloudWatch. Both show an estimate first and run only when you accept it. [TODO Ansh: state whether the regular scan's own AWS API reads can be billed.]"],
          ["Does emfirge create anything in my account?", "Only the IAM role, through the CloudFormation stack you create. Delete the stack and it is gone."],
          ["Do I pay for an AI model through emfirge?", "No. Emfirge has no AI inside. Your own agent's model usage is billed by whoever provides that model."],
          ["Is there a free tier after beta?", "[TODO Ansh: not decided.]"],
          ["Can I run it myself?", "The engine is AGPL-3.0 and you can read and deploy it. It is not set up for easy self-hosting and is not supported."],
        ] },
      ],
    },
  ],
};
