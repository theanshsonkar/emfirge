import { WORLD, type WorldCard, type WorldMock } from "@/content";
import { cn } from "@/lib/cn";
import { Frame } from "./Frame";

function Pill({ state }: { state: "block" | "pass" | "live" }) {
  const c =
    state === "block"
      ? "bg-block-on-dark/15 text-block-on-dark"
      : state === "pass"
        ? "bg-pass-on-dark/15 text-pass-on-dark"
        : "bg-mist/10 text-mist";
  return <span className={cn("rounded-full px-2 py-0.5 text-xs font-medium", c)}>{state === "live" ? "live" : state === "block" ? "Block" : "Pass"}</span>;
}

function Mock({ mock, tone }: { mock: WorldMock; tone: WorldCard["tone"] }) {
  const dark = tone === "dark";
  const shell = cn(
    "overflow-hidden rounded-xl font-mono text-[12px] leading-5 shadow-mock",
    dark ? "border border-forest-line bg-forest-deep text-mist" : "border border-line bg-white text-ink-2",
  );
  const muted = dark ? "text-mist-2" : "text-ink-3";

  if (mock.kind === "table") {
    return (
      <div className={shell}>
        <table className="w-full min-w-[420px] text-left">
          <thead className={muted}>
            <tr className="border-b border-forest-line">
              {mock.head.map((h) => (
                <th key={h} className="px-3 py-2 font-normal">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {mock.rows.map((r) => (
              <tr key={r[0]} className="border-b border-forest-line last:border-0">
                {r.map((c, i) => (
                  <td key={i} className={cn("whitespace-nowrap px-3 py-2", i === 0 ? "text-white" : i === 2 && c === "live" ? "text-pass-on-dark" : "")}>
                    {c}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  if (mock.kind === "branches") {
    return (
      <ul className={cn(shell, "divide-y divide-forest-line text-[13px]")}>
        {mock.rows.map((r) => (
          <li key={r.name} className="flex items-center gap-3 px-3 py-2.5">
            <span className={muted}>{r.name}</span>
            <span className="flex-1 text-white">{r.branch}</span>
            <Pill state={r.state} />
          </li>
        ))}
      </ul>
    );
  }
  if (mock.kind === "doc") {
    return (
      <div className={cn(shell, "space-y-1.5 px-4 py-4 text-[13px]")}>
        {mock.lines.map((l, i) => (
          <p key={i} className={cn(i === 0 && "text-ink")}>
            {l.text}
          </p>
        ))}
      </div>
    );
  }
  return (
    <ol className={cn(shell, "divide-y divide-line text-[13px]")}>
      {mock.rows.map((r) => (
        <li key={r.text} className="flex gap-3 px-3 py-2.5">
          <time className="text-ink-3">{r.time}</time>
          <span>{r.text}</span>
        </li>
      ))}
    </ol>
  );
}

export function World() {
  return (
    <section aria-labelledby="world-title" className="border-b border-line">
      <Frame>
        <div className="px-4 pb-10 pt-16 sm:px-8 lg:px-12 lg:pt-24">
          <h2
            id="world-title"
            className="max-w-[22ch] text-balance text-4xl font-medium leading-[1.05] tracking-[-0.035em] text-ink sm:text-5xl lg:text-[56px]"
          >
            {WORLD.title}
          </h2>
          <p className="mt-5 max-w-[56ch] text-base text-ink-2">{WORLD.body}</p>
        </div>
        <ul className="grid gap-4 px-4 pb-16 sm:px-8 md:grid-cols-2 lg:px-12 lg:pb-24">
          {WORLD.cards.map((c) => (
            <li key={c.title} className="flex flex-col overflow-hidden rounded-xl border border-line bg-white">
              <div className="p-6">
                <h3 className="text-[22px] font-medium leading-[1.3] tracking-[-0.02em] text-ink">{c.title}</h3>
                <p className="mt-2 max-w-[34ch] text-base text-ink-2">{c.body}</p>
              </div>
              <div className="relative mt-auto h-[220px] overflow-hidden bg-gradient-to-t from-brand/15 to-transparent">
                <div role="img" aria-label={c.mockLabel} className="absolute left-6 right-0 top-2 sm:left-8">
                  <div aria-hidden="true">
                    <Mock mock={c.mock} tone={c.tone} />
                  </div>
                </div>
              </div>
            </li>
          ))}
        </ul>
      </Frame>
    </section>
  );
}
