import type { Page } from "@/content/types";
import { Shell } from "./Shell";
import { Blocks, Inline } from "./Blocks";
import { CopyMd } from "./CopyMd";
import { Footer } from "./Sections";
import { TodoList } from "./Todo";

export function DocPage({ page }: { page: Page }) {
  const mdUrl = `/${page.slug}.md`;
  const toc = page.sections.map((s) => ({ id: s.id, label: s.title.replace(/^\d+\.\s*/, "") }));
  return (
    <Shell toc={toc} mdUrl={mdUrl}>
      <span id="top" />
      <header className="dp-head">
        <h1 className="dp-h1">{page.h1.split("\n").map((l, i) => <span key={i}>{i > 0 && <br />}{l}</span>)}</h1>
        <p className="dp-lead"><Inline x={page.lead} /></p>
        <CopyMd mdUrl={mdUrl} />
      </header>
      {page.intro && <Blocks blocks={page.intro} />}
      {page.sections.map((s) => (
        <section id={s.id} key={s.id} className="dp-sec">
          <hr className="hr" />
          <h2 className="h2" data-reveal>{s.title}</h2>
          <Blocks blocks={s.blocks} />
        </section>
      ))}
      <TodoList page={page.slug} />
      <Footer />
    </Shell>
  );
}
