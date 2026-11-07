import {
  ChevronLeft,
  ChevronRight,
  Database,
  Eye,
  GitBranch,
  Info,
  KeyRound,
  Search,
  Globe,
  Timer,
  Wallet,
} from "lucide-react";
import { BRANCH } from "@/content";
import { cn } from "@/lib/cn";
import { H2 } from "./Heading";
import { LogoMark } from "./Logo";
import { MacWindow } from "./MacWindow";

const ICONS: Record<string, { bg: string; el: React.ReactNode }> = {
  data: { bg: "bg-[#0A84FF]", el: <Database size={14} /> },
  exposure: { bg: "bg-[#FF9F0A]", el: <Eye size={14} /> },
  money: { bg: "bg-[#30B455]", el: <Wallet size={14} /> },
  availability: { bg: "bg-[#8E5CF0]", el: <Timer size={14} /> },
  control: { bg: "bg-[#8E8E93]", el: <KeyRound size={14} /> },
  world: { bg: "bg-[#FF375F]", el: <Globe size={14} /> },
};

function IconSquare({ k }: { k: string }) {
  const i = ICONS[k];
  return (
    <span className={cn("flex h-6 w-6 shrink-0 items-center justify-center rounded-[6px] text-white", i.bg)}>
      {i.el}
    </span>
  );
}

function InfoDot() {
  return <Info size={15} strokeWidth={1.6} className="shrink-0 text-black/30" aria-hidden="true" />;
}

export function BranchWindow() {
  const { card, legend, top, rows, sidebar, selected } = BRANCH;
  return (
    <section id="branch" data-nav="how" className="px-4 pb-[88px] md:pb-[120px]">
      <H2>{BRANCH.title}</H2>

      <div className="mx-auto mt-10 w-full max-w-[780px]">
        <MacWindow variant="settings" lightsClassName="max-sm:left-[16px]">
          <div className="grid sm:grid-cols-[212px_1fr]">
            {/* sidebar */}
            <aside className="hidden bg-sidebar px-2.5 pb-4 pt-[46px] shadow-[inset_-0.5px_0_0_rgba(0,0,0,0.1)] sm:block">
              <div className="flex h-7 items-center gap-1.5 rounded-lg bg-black/[0.06] px-2 text-[13px] text-ink-3">
                <Search size={12} strokeWidth={2} />
                search
              </div>
              <div className="mt-3 flex items-center gap-2.5 px-1.5 py-1">
                <span className="flex h-[34px] w-[34px] items-center justify-center rounded-full bg-ink text-white">
                  <LogoMark size={16} />
                </span>
                <span className="min-w-0 leading-[15px]">
                  <span className="block truncate text-[13px] font-medium text-ink">your aws account</span>
                  <span className="block text-[11px] text-ink-3">read-only role</span>
                </span>
              </div>
              <p className="mb-1 mt-4 px-2 text-[11px] font-semibold leading-4 text-ink-3">branches</p>
              <ul className="space-y-0.5">
                {sidebar.map((s, i) => {
                  const sel = i === selected;
                  return (
                    <li
                      key={s}
                      className={cn(
                        "flex h-[28px] items-center gap-2 rounded-[7px] px-1.5 text-[13px]",
                        sel ? "bg-[#0A67F5] text-white" : "text-ink",
                      )}
                    >
                      <span
                        className={cn(
                          "flex h-5 w-5 items-center justify-center rounded-[5px] text-white",
                          i === 0 ? "bg-pass" : sel ? "bg-white/25" : "bg-[#8E8E93]",
                        )}
                      >
                        <GitBranch size={12} strokeWidth={2.2} />
                      </span>
                      {s}
                    </li>
                  );
                })}
              </ul>
            </aside>

            {/* content */}
            <div className="min-w-0 bg-surface">
              <div className="flex h-[52px] items-center gap-3 pl-[84px] pr-4 sm:pl-3.5">
                <div className="hidden h-7 w-[58px] items-center justify-around rounded-full bg-white shadow-hairline sm:flex">
                  <ChevronLeft size={15} className="text-ink" />
                  <ChevronRight size={15} className="text-black/25" />
                </div>
                <span className="text-[15px] font-semibold tracking-[-0.01em] text-ink">branch #2</span>
              </div>

              <div className="space-y-3 px-3.5 pb-3.5">
                {/* summary card */}
                <div className="rounded-[10px] bg-[#F8F8F9] p-3.5 shadow-hairline">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="text-[13px] font-semibold leading-4 text-ink">{card.title}</p>
                      <p className="mt-0.5 text-[12px] leading-4 text-ink-3">{card.sub}</p>
                    </div>
                    <p className="hidden shrink-0 text-[12px] leading-4 text-ink-3 sm:block">{card.right}</p>
                  </div>
                  <div className="mt-3 flex h-[18px] gap-[2px] overflow-hidden rounded-[5px]" role="img" aria-label="6 of 6 checks passed">
                    {legend.map((l) => (
                      <span key={l} className="flex-1 bg-pass" />
                    ))}
                  </div>
                  <ul className="mt-2 flex flex-wrap gap-x-3 gap-y-1">
                    {legend.map((l) => (
                      <li key={l} className="flex items-center gap-1 text-[11px] leading-4 text-ink-3">
                        <span className="h-[7px] w-[7px] rounded-full bg-pass" />
                        {l}
                      </li>
                    ))}
                  </ul>
                </div>

                {/* list card */}
                <ul className="overflow-hidden rounded-[10px] bg-[#F8F8F9] shadow-hairline">
                  <li className="flex h-[46px] items-center gap-2.5 pl-3 pr-3">
                    <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-[6px] bg-ink text-white">
                      <LogoMark size={13} />
                    </span>
                    <span className="min-w-0 flex-1 leading-[15px]">
                      <span className="block truncate text-[13px] font-semibold text-ink">{top.title}</span>
                      <span className="block truncate text-[11px] text-ink-3">{top.sub}</span>
                    </span>
                    <span className="text-[13px] font-medium text-pass">{top.value}</span>
                    <InfoDot />
                  </li>
                  {rows.map((r) => (
                    <li key={r.key} className="flex h-[38px] items-center gap-2.5 pl-3 pr-3">
                      <IconSquare k={r.key} />
                      <span className="flex h-full min-w-0 flex-1 items-center justify-between gap-2 shadow-[0_-0.5px_0_0_rgba(0,0,0,0.1)]">
                        <span className="text-[13px] text-ink">{r.name}</span>
                        <span className="truncate text-right text-[13px] text-ink-3">{r.value}</span>
                      </span>
                      <InfoDot />
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </MacWindow>
      </div>

      <div className="mx-auto mt-10 max-w-[520px] space-y-3 text-center text-[15px] leading-[22px] text-ink-2">
        {BRANCH.lines.map((l) => (
          <p key={l} className="text-pretty">
            {l}
          </p>
        ))}
      </div>
    </section>
  );
}
