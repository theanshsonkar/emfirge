import {
  Code2,
  FileCode2,
  FileText,
  GitBranch,
  KeyRound,
  ListChecks,
  Lock,
  ScrollText,
  SquareTerminal,
} from "lucide-react";
import { PRICING } from "@/content";
import { H2 } from "./Heading";
import { LogoMark } from "./Logo";

const ICONS: Record<string, React.ReactNode> = {
  terminal: <SquareTerminal size={16} />,
  branch: <GitBranch size={16} />,
  checks: <ListChecks size={16} />,
  code: <FileCode2 size={16} />,
  key: <KeyRound size={16} />,
  lock: <Lock size={16} />,
  file: <FileText size={16} />,
  record: <ScrollText size={16} />,
  open: <Code2 size={16} />,
};

export function PricingCard() {
  return (
    <section id="pricing" data-nav="pricing" className="px-4 pb-[88px] md:pb-[120px]">
      <H2>{PRICING.title}</H2>
      <div className="mx-auto mt-10 w-full max-w-[360px] overflow-hidden rounded-2xl bg-surface shadow-[0_0_0_0.5px_rgba(0,0,0,0.12),0_20px_50px_-28px_rgba(0,0,0,0.18)]">
        <div className="bg-gradient-to-b from-[#E4E4E6] via-[#EFEFF0] to-white px-6 pb-5 pt-6">
          <div className="flex items-center gap-3.5">
            <LogoMark size={40} />
            <div className="leading-tight">
              <p className="text-[24px] font-semibold italic tracking-[-0.03em] text-ink">{PRICING.badge}</p>
              <p className="mt-0.5 text-[14px] leading-[21px] text-ink-2">{PRICING.sub}</p>
            </div>
          </div>
          <p className="mt-6 flex items-baseline gap-1.5">
            <span className="text-[36px] font-semibold leading-none tracking-[-0.04em] text-ink">{PRICING.price}</span>
            <span className="text-[14px] text-ink-2">{PRICING.per}</span>
          </p>
          <p className="mt-1.5 text-[13px] leading-[19px] text-ink-3">{PRICING.note}</p>
        </div>
        <div className="px-6 pb-6 pt-2">
          <ul className="space-y-3 text-[14px] leading-[21px] text-ink">
            {PRICING.features.map((f) => (
              <li key={f.t} className="flex items-start gap-2.5">
                <span className="mt-[2.5px] shrink-0 text-ink" aria-hidden="true">
                  {ICONS[f.icon]}
                </span>
                {f.t}
              </li>
            ))}
          </ul>
          <a
            href={PRICING.cta.href}
            className="mt-6 flex h-10 w-full items-center justify-center rounded-full bg-ink text-[14px] font-medium text-white transition-opacity hover:opacity-85"
          >
            {PRICING.cta.label}
          </a>
        </div>
      </div>
    </section>
  );
}
