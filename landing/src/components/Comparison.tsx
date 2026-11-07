import { Section, H2 } from "./ui/Section";
import { COMPARISON } from "@/content";

export function Comparison() {
  return (
    <Section tone="paper" aria-labelledby="compare-h">
      <H2 id="compare-h" className="max-w-[22ch]">Coding agents got a harness. Cloud agents didn&apos;t. Until now.</H2>
      <div className="mt-12 overflow-hidden rounded-2xl border border-ink/15">
        <table className="w-full border-collapse text-left">
          <thead>
            <tr className="bg-ink">
              <th scope="col" className="w-[34%] px-4 py-4 font-mono text-xs font-medium uppercase tracking-wider text-muted md:px-6">
                Coding harness
              </th>
              <th scope="col" className="px-4 py-4 font-mono text-xs font-medium uppercase tracking-wider text-forge md:px-6">
                Emfirge
              </th>
            </tr>
          </thead>
          <tbody>
            {COMPARISON.map((r) => (
              <tr key={r.coding} className="border-t border-ink/15 align-top">
                <th scope="row" className="px-4 py-5 text-base font-medium md:px-6 md:text-lg">{r.coding}</th>
                <td className="px-4 py-5 text-[15px] leading-relaxed md:px-6 md:text-base">
                  <strong className="font-semibold">{r.name}</strong>
                  <span className="text-ink/75">: {r.body}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  );
}
