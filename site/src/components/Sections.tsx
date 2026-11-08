import { CTA, FOOTER, LINKS, METRICS, PRODUCTION, RUNS, TRUST, WHAT, WRITING, FIGURE } from "@/content/site";
import { Mark } from "@/graphics/Mark";
import { Delta, CTA_DELTA } from "@/graphics/Delta";
import { Tile } from "@/graphics/Tile";
import { Iso } from "@/graphics/Iso";
import { Figure1 } from "@/graphics/Figure1";
import { Ext } from "./Icons";

const fmt = (n: number) => n.toLocaleString("en-US");

export function Figure() {
  return (
    <figure className="fig" data-reveal style={{ margin: "58px 0 0" }}>
      <div className="fig-frame"><Figure1 /></div>
      <figcaption className="cap">{FIGURE.caption}</figcaption>
    </figure>
  );
}

export function What() {
  return (
    <section id="what-we-do" style={{ scrollMarginTop: 40 }}>
      <hr className="hr" />
      <h2 className="h2" data-reveal>{WHAT.title}</h2>
      {WHAT.rows.map((r) => (
        <div className="row" key={r.title} data-reveal>
          <div className="tilec"><Tile kind={r.tile} /></div>
          <div><h3>{r.title}</h3><p>{r.text}</p></div>
        </div>
      ))}
      <p className="muted" data-reveal>{WHAT.note}</p>
      <a className="arrow" href={LINKS.how} data-reveal>{WHAT.more} <Ext size={10} /></a>
    </section>
  );
}

export function SourcesCard() {
  const m = METRICS;
  const max = Math.max(...m.sources.bars.map((b) => b.value));
  return (
  <div className="card tall" data-reveal style={{ display: "flex", flexDirection: "column" }}>
    <h4>{m.sources.title}</h4><div className="label">{m.sources.sub}</div>
    <div className="num" style={{ marginTop: 22 }}>{m.sources.headline}</div>
    <p style={{ fontSize: 13, lineHeight: "19.5px", color: "var(--ink-2)", margin: "6px 0 0" }}>{m.sources.headlineLabel}</p>
    <div className="div" />
    <div style={{ flex: 1, display: "flex", flexDirection: "column", justifyContent: "flex-end" }}>
      <div className="chart" style={{ height: 230, marginTop: 24 }}>
        {m.sources.bars.map((b) => (
          <div key={b.label} className={`bar ${b.own ? "own" : ""}`} style={{ ["--h" as string]: `${(b.value / max) * 100}%` }} title={`${b.name}: ${b.value}`}>
            <span>{b.value}</span>
          </div>
        ))}
      </div>
      <div className="barlab">{m.sources.bars.map((b) => <span key={b.label}>{b.label}</span>)}</div>
    </div>
    <div className="links"><a href={`${LINKS.github}/tree/main/backend/app/data`}>{m.sources.link} <Ext size={9} /></a></div>
  </div>
  );
}

export function SameCard({ style }: { style?: React.CSSProperties }) {
  const m = METRICS;
  return (
  <div className="card" data-reveal style={style}>
    <h4>{m.same.title}</h4><div className="label">{m.same.sub}</div>
    <table className="same">
      <thead><tr><th>{m.same.cols[0]}</th><th>{m.same.cols[1]}</th></tr></thead>
      <tbody>
        {m.same.rows.map((r, i) => (
          <tr key={r.name}><td>{r.name}</td><td className="d"><i className="gd" style={{ ["--i" as string]: i }} />Same verdict · {r.law ?? r.note}</td></tr>
        ))}
      </tbody>
    </table>
    <p style={{ fontSize: 13, lineHeight: "19.5px", color: "var(--ink-2)", margin: "16px 0 0" }}>{m.same.foot}</p>
    <div className="links"><a href={`${LINKS.github}/tree/main/backend/tests/laws`}>{m.same.link} <Ext size={9} /></a></div>
  </div>
  );
}

export function Production() {
  const m = METRICS;
  return (
    <section id="in-production" style={{ scrollMarginTop: 40 }}>
      <hr className="hr" style={{ marginTop: 70 }} />
      <div className="label" style={{ marginTop: 28, color: "var(--ink-3)", fontSize: 10.5 }} data-reveal>{PRODUCTION.label}</div>
      <p className="statement" data-reveal>
        Our <b>promise</b> is a world your agent can <b>trust</b>: true facts, unknowns marked honestly, and nothing that ever writes to your cloud.
      </p>
      <div className="grid">
        <div className="stack">
          <div className="card" data-reveal>
            <h4>{m.tests.title}</h4><div className="label">{m.tests.sub}</div>
            <table className="tbl">
              <thead><tr><th /><th>{m.tests.cols[0]}</th></tr></thead>
              <tbody>
                {m.tests.rows.map((r) => (
                  <tr key={r.name}><td className="k">{r.name}</td><td className="v"><span className="num" style={{ fontSize: 28, lineHeight: "32px" }}>{fmt(r.value)}</span></td></tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="card" data-reveal>
            <h4>{m.laws.title}</h4><div className="label">{m.laws.sub}</div>
            <div className="num" style={{ marginTop: 14 }}>{m.laws.value}</div>
            <div className="heat" aria-label={`${m.laws.value} laws`}>
              {Array.from({ length: m.laws.value }, (_, i) => <i key={i} style={{ ["--i" as string]: i }} />)}
            </div>
          </div>
          <div className="card" data-reveal>
            <h4>{m.types.title}</h4><div className="label">{m.types.sub}</div>
            <div className="num" style={{ marginTop: 14 }}>{m.types.value}</div>
          </div>
        </div>
        <SourcesCard />
      </div>
      <SameCard style={{ marginTop: 13 }} />
      <blockquote className="quote" data-reveal>
        <p>“A change Emfirge can&apos;t model <b>can&apos;t pass</b>. A missing check is <b>reported, not hidden</b>.”</p>
        <small>{m.quoteBy}</small>
      </blockquote>
    </section>
  );
}

export function Runs() {
  return (
    <section id="runs" style={{ scrollMarginTop: 40 }}>
      <hr className="hr" style={{ marginTop: 70 }} />
      <h2 className="h2" style={{ fontSize: 24, lineHeight: "30px", marginTop: 32 }} data-reveal>emfirge runs wherever<br />your agent runs.</h2>
      <p className="prose" style={{ margin: "30px 0 0", fontSize: 17, lineHeight: "27px" }} data-reveal>{RUNS.text}</p>
      <a className="ext" href={LINKS.quickstart} style={{ marginTop: 22, fontSize: 15, display: "inline-flex" }} data-reveal>{RUNS.link} <Ext size={10} /></a>
      <div className="cards3">
        {RUNS.cards.map((c) => (
          <div className="ic" key={c.n} data-reveal>
            <div className="hd"><span style={{ fontFamily: "inherit", fontSize: 15, color: "var(--ink)", lineHeight: "21px" }}>{c.title}</span><span>{c.n}</span></div>
            <div className="art"><Iso kind={c.art as "laptop"} /></div>
            <div className="c3" />
          </div>
        ))}
      </div>
    </section>
  );
}

function TrustMark({ kind }: { kind: string }) {
  const p = { fill: "none", stroke: "#0B1015", strokeWidth: 1.4 } as const;
  return (
    <svg width="44" height="44" viewBox="0 0 44 44" aria-hidden="true">
      {kind === "key" && <g {...p}><circle cx="15" cy="22" r="7" /><path d="M22 22H38M32 22V28M37 22V26" /><circle cx="15" cy="22" r="2" fill="#0A7A4B" stroke="none" /></g>}
      {kind === "token" && <g {...p}><rect x="6" y="14" width="32" height="16" /><path d="M12 22H18M22 22H26" /><path d="M30 19V25" stroke="#0A7A4B" strokeWidth="2.4" /><path d="M10 10V14M34 10V14M10 30V34M34 30V34" opacity=".4" /></g>}
      {kind === "open" && <g {...p}><path d="M16 14L8 22L16 30" /><path d="M28 14L36 22L28 30" /><path d="M25 12L19 32" stroke="#0A7A4B" strokeWidth="2" /></g>}
    </svg>
  );
}

export function Trust() {
  return (
    <section id="trust" style={{ scrollMarginTop: 40 }}>
      <hr className="hr" style={{ marginTop: 34 }} />
      <h2 className="h2" style={{ marginTop: 28 }} data-reveal>{TRUST.title}</h2>
      <p className="muted" style={{ marginTop: 18 }} data-reveal>{TRUST.text}</p>
      <div className="tiles3" data-reveal>
        {TRUST.tiles.map((t) => (
          <div className="cert" key={t.label}><TrustMark kind={t.mark} /><span className="label">{t.label}</span>{t.sub && <small>{t.sub}</small>}</div>
        ))}
      </div>
      <div className="links" style={{ gap: 34, marginTop: 28, fontSize: 15 }}>
        {TRUST.links.map((l) => <a key={l.label} href={l.href}>{l.label} <Ext size={10} /></a>)}
      </div>
    </section>
  );
}

export function Cta() {
  return (
    <section className="cta" aria-label="Get started" data-reveal>
      <Delta opts={CTA_DELTA} className="cv" />
      <div className="cin">
        <h2>{CTA.title}</h2>
        <p>{CTA.text}</p>
        <a className="btn" href={LINKS.quickstart}><span className="tile"><Mark size={24} trunk="#fff" branch="#fff" /></span>{CTA.button}</a>
      </div>
    </section>
  );
}

export function Writing() {
  return (
    <section id="writing" className="wr" style={{ scrollMarginTop: 40, marginTop: 90 }}>
      <h2 className="h2" style={{ marginTop: 0 }} data-reveal>{WRITING.title}</h2>
      {WRITING.rows.map((r) => (
        <div className="it" key={r} data-reveal><span>{r}</span><span className="label">{WRITING.tag}</span></div>
      ))}
    </section>
  );
}

export function Footer() {
  return (
    <footer className="ft">
      <div className="ft-top">
        <div><a href="/" className="logo" style={{ fontSize: 20 }}><Mark size={24} />emfirge</a><p>{FOOTER.tagline}</p></div>
        <div className="ft-cols">
          {FOOTER.cols.map((c) => (
            <div key={c.h}>
              <div className="label" style={{ color: "var(--ink-3)" }}>{c.h}</div>
              <ul>{c.links.map(([l, h]) => <li key={l}>{h ? <a href={h}>{l}</a> : <span style={{ fontSize: 13, lineHeight: "28px", color: "var(--ink-2)" }}>{l}</span>}</li>)}</ul>
            </div>
          ))}
        </div>
      </div>
      <div className="ft-bot">
        <div className="l"><span>{FOOTER.legal}</span><a href={LINKS.privacy}>Privacy</a><a href={LINKS.security}>Security</a></div>
        <div className="r"><span><i className="sdot" />{FOOTER.status}</span><a href="#top">Back to top ↑</a></div>
      </div>
    </footer>
  );
}
