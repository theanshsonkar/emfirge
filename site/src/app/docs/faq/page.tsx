import { A, Callout, DocHeader, H2, Lead, P, PrevNext, Strong } from "@/components/docs/ui";
import { prevNext } from "@/lib/nav";

export const metadata = {
  title: "FAQ · Emfirge Docs",
  description: "Simple answers to common questions about Emfirge, with no cloud-security jargon.",
};

export default function Page() {
  const { prev, next } = prevNext("/docs/faq");

  return (
    <>
      <DocHeader eyebrow="Get Started" title="FAQ">
        <Lead>
          The simple version of Emfirge: what it does, what it can see, and what happens when you
          connect your AWS account. No cloud-security dictionary required.
        </Lead>
      </DocHeader>

      <H2>What does Emfirge actually do?</H2>
      <P>
        Emfirge looks at how the parts of your AWS account connect, points out the routes an attacker
        could use, and helps you check whether a security fix would make things safer before you
        apply it. Think of it as a <Strong>map of your cloud with a safe practice mode</Strong>.
      </P>

      <H2>Do I need to be a security expert?</H2>
      <P>
        No. You can ask normal questions like “What should I fix first?”, “How could someone reach my
        database?”, or “Would this change help?” Emfirge does the analysis, and your assistant explains
        the answer in everyday language.
      </P>

      <H2>What do I need before I start?</H2>
      <P>
        You need an AWS account, the AWS region you want to check, and a read-only connection for
        Emfirge. The setup guide walks you through it, and you can remove that connection whenever you
        want. Start with the <A href="/docs/quickstart">Quickstart</A> when you are ready.
      </P>

      <H2>What is MCP, and do I need to learn it?</H2>
      <P>
        MCP is simply the connection that lets an AI assistant use tools like Emfirge. You do not need
        to learn how it works. The installer connects it to supported desktop assistants for you. If
        you prefer a browser, you can use the <A href="https://app.emfirge.cloud">Emfirge dashboard</A>.
      </P>

      <H2>Can I try it without connecting my account?</H2>
      <P>
        Yes. The demo uses made-up infrastructure with the real Emfirge analysis engine, so you can
        see the kind of answers you will get without sharing anything from your AWS account. The demo
        details are in the <A href="/docs/quickstart">Quickstart</A>.
      </P>

      <H2>Will Emfirge change or delete anything?</H2>
      <P>
        No. Emfirge has read-only access. When it tests a possible fix, it works on a temporary copy of
        your cloud map, not on your real AWS account. It shows you what would change, and you decide
        what to do next.
      </P>

      <H2>Is it safe to connect my AWS account?</H2>
      <P>
        Emfirge uses a read-only role that belongs to you. Its access is temporary, it cannot make AWS
        changes, and you can revoke it by deleting the setup stack in your AWS account. The full details
        are on the <A href="/docs/security">Security model</A> page.
      </P>

      <H2>Who can see my AWS names and IDs?</H2>
      <P>
        Emfirge needs the real details on its backend to read and understand your account. Before the
        result reaches your AI assistant, the default privacy mode replaces recognized names and IDs
        with labels such as “NAME_132” on your computer. Some labels created from the cloud map can
        still appear, so review sensitive results before sharing a chat. See <A href="/docs/privacy">Privacy modes</A> for the honest details.
      </P>

      <H2>How long does a scan take?</H2>
      <P>
        Usually around 30 to 60 seconds. Bigger or more complicated accounts may take longer. Once the
        scan is finished, you can keep asking questions about that result without running a new scan
        each time.
      </P>

      <H2>Is it free?</H2>
      <P>
        Yes, the hosted free tier includes five scans per AWS account each day. You do not need to sign
        up or create an API key. Looking through findings, attack routes, possible fixes, and compliance
        checks after a scan does not use another scan.
      </P>

      <H2>What should I do after it finds a problem?</H2>
      <P>
        Start with the item Emfirge ranks first. Ask why it matters, see which attack routes it affects,
        and test the suggested fix. Emfirge gives you evidence; it does not force a change. You or your
        team still review and apply the final fix.
      </P>

      <H2>Does it cover everything in AWS?</H2>
      <P>
        Not yet. Emfirge covers the common AWS services and security relationships it knows how to
        model, but AWS is huge. Treat it as another strong set of eyes, not a promise that every possible
        issue has been found.
      </P>

      <H2>Can I run Emfirge on my own servers?</H2>
      <P>
        Yes. If your company needs to keep the backend inside its own environment, follow the <A href="/docs/self-host">Self-hosting</A> guide. That page is more technical, so you may want an engineer to help with it.
      </P>

      <Callout type="tip" title="Still unsure where to begin?">
        Open the <A href="/docs/quickstart">Quickstart</A> and try the demo first. You can see Emfirge
        work before connecting your own AWS account.
      </Callout>

      <PrevNext prev={prev} next={next} />
    </>
  );
}
