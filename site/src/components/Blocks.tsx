import React from "react";
import type { Block, Entry, Plan } from "@/content/types";
import { Delta, PLAN_DELTA } from "@/graphics/Delta";
import { CopyBar } from "./Hero";
import { CodeBlock } from "./CodeBlock";
import { Fig } from "./Fig";
import { Ext } from "./Icons";
import { SameCard, SourcesCard } from "./Sections";
import { TodoMark } from "./Todo";

// Inline Markdown subset: `code`, **bold**, [label](href). A stray [TODO Ansh: ...] token renders only with ?todo=1.
const TOK = /(\[TODO Ansh:[^\]]*\]|\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\([^)]+\))/g;
export function Inline({ x }: { x: string }) {
  return (
    <>
      {x.split(TOK).map((p, i) => {
        if (!p) return null;
        if (p.startsWith("[TODO Ansh:")) return <TodoMark key={i} text={p} />;
        if (p.startsWith("**")) return <b key={i}>{p.slice(2, -2)}</b>;
        if (p.startsWith("`")) return <code className={`ic-code${p.length <= 32 ? " nw" : ""}`} key={i}>{p.slice(1, -1)}</code>;
        const m = /^\[([^\]]+)\]\(([^)]+)\)$/.exec(p);
        if (m) {
          const ext = /^(https?:|mailto:)/.test(m[2]);
          return ext && m[2].startsWith("http") ? <a className="uline" key={i} href={m[2]} target="_blank" rel="noreferrer">{m[1]}</a> : <a className="uline" key={i} href={m[2]}>{m[1]}</a>;
        }
        return <React.Fragment key={i}>{p}</React.Fragment>;
      })}
    </>
  );
}

function PlanCard({ plan }: { plan: Plan }) {
  return (
    <div className="plan" data-reveal>
      <div className="plan-l">
        <div className="plan-h">
          <Delta opts={PLAN_DELTA} className="cv" />
          <div className="plan-t"><span>{plan.name}</span><b>{plan.price}</b><small>{plan.unit}</small></div>
        </div>
        <a className="btn btn-s" href={plan.cta.href}>{plan.cta.label}</a>
      </div>
      <div className="plan-b">
        <p className="plan-blurb">{plan.blurb}</p>
        <ul>{plan.includes.map((i) => <li key={i}><svg width="11" height="11" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden="true"><path d="M3 7.5L6 10.5L11 4" /></svg><span><Inline x={i} /></span></li>)}</ul>
      </div>
      <p className="plan-foot"><Inline x={plan.foot} /></p>
    </div>
  );
}

function Entries({ items }: { items: Entry[] }) {
  return (
    <div className="clog">
      {items.map((e) => (
        <article key={e.iso + e.title} data-reveal>
          <i className="cdot" aria-hidden="true" />
          <div className="chead"><span className="ctag">{e.tag}</span><time dateTime={e.iso}>{e.date}</time></div>
          <h3>{e.title}</h3>
          <p>{e.summary}</p>
          <div className="label">Improvements</div>
          <ul>{e.improvements.map((i) => <li key={i}><Inline x={i} /></li>)}</ul>
          {e.fixes && <><div className="label">Fixes</div><ul>{e.fixes.map((i) => <li key={i}><Inline x={i} /></li>)}</ul></>}
        </article>
      ))}
    </div>
  );
}

export function Blocks({ blocks }: { blocks: Block[] }) {
  return (
    <>
      {blocks.map((b, i) => {
        switch (b.t) {
          case "p": return <p className="dp" key={i} data-reveal><Inline x={b.x} /></p>;
          case "lede": return <p className="dp-lede" key={i} data-reveal><Inline x={b.x} /></p>;
          case "h3": return <h3 className="dp-h3" key={i} data-reveal><Inline x={b.x} /></h3>;
          case "code": return <div key={i} data-reveal><CodeBlock title={b.title} text={b.x} /></div>;
          case "table": return (
            <div className="dp-tw" key={i} data-reveal>
              <table className="dp-t" data-cols={b.head.length} data-ops={b.ops ? "" : undefined}>
                <thead><tr>{b.head.map((h) => <th key={h}>{h}</th>)}</tr></thead>
                <tbody>{b.rows.map((r, j) => (
                  <tr key={j}>{r.map((c, k) => {
                    const cls = `${k === 0 ? "k" : ""} ${b.mono?.includes(k) ? "m" : ""}`;
                    if (b.ops?.includes(k)) {
                      // add / modify / delete: "yes" in the wide table, the figure's pips in the stacked phone layout
                      const on = c === "yes", op = b.head[k].toLowerCase();
                      return <td key={k} className="op" data-on={on ? "1" : "0"} data-label={b.head[k]}><span className="yn">{c}</span><i className={`pip pip-${op}`} aria-hidden="true" /><span className="pl">{op}<span className="sr">: {on ? "yes" : "no"}</span></span></td>;
                    }
                    return <td key={k} className={`${cls}${b.ops && k === b.head.length - 1 ? " nt" : ""}`} data-label={b.head[k]}><Inline x={c} /></td>;
                  })}</tr>
                ))}</tbody>
              </table>
            </div>
          );
          case "list": return <ul className="dp-ul" key={i} data-reveal>{b.items.map((x) => <li key={x}><Inline x={x} /></li>)}</ul>;
          case "card": return (
            <div className="dp-card" key={i} data-reveal>
              {b.parts.map((p) => (
                <div key={p.label}>
                  <div className="label">{p.label}</div>
                  {p.lines.map((l) => <div className="ln" key={l.x}><span>{l.x}</span>{l.tag && <em>{l.tag}</em>}</div>)}
                </div>
              ))}
            </div>
          );
          case "note": return <p className="dp-note" key={i} data-reveal><Inline x={b.x} /></p>;
          case "fig": return <Fig key={i} id={b.id} caption={b.caption} />;
          case "link": return <a className="arrow" key={i} href={b.href} data-reveal>{b.label} <Ext size={10} /></a>;
          case "faq": return <div className="dp-faq" key={i}>{b.items.map(([q, a]) => <div key={q} data-reveal><h3><Inline x={q} /></h3><p><Inline x={a} /></p></div>)}</div>;
          case "sources": return <div className="dp-card-wrap" key={i}><SourcesCard /></div>;
          case "same": return <div className="dp-card-wrap" key={i}><SameCard /></div>;
          case "setup": return <div className="dp-setup" key={i} data-reveal><CopyBar /></div>;
          case "details": return (
            <details className="dp-det" key={i} data-reveal>
              <summary className="label">{b.summary}</summary>
              <div className="dp-det-b"><Blocks blocks={b.blocks} /></div>
            </details>
          );
          case "plan": return <PlanCard key={i} plan={b.plan} />;
          case "entries": return <Entries key={i} items={b.items} />;
        }
      })}
    </>
  );
}
