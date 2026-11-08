import { COMMAND, FOOTER, LINKS } from "@/content";
import { TestMark } from "./TestMark";

export function Footer() {
  return (
    <footer className="bg-black text-white">
      <div className="mx-auto max-w-[1440px] px-4 py-16 sm:px-8 lg:py-24">
        <div className="flex flex-col gap-8 sm:flex-row sm:items-center sm:gap-12">
          <TestMark ring size={160} className="size-[104px] shrink-0 sm:size-[160px]" />
          <p className="display max-w-[16em] text-[30px] sm:text-[44px]">{FOOTER.line}</p>
        </div>
        <p className="mt-12 w-fit max-w-full overflow-x-auto whitespace-nowrap rounded-md border-2 border-white px-4 py-2.5 font-mono text-[14px]">
          {COMMAND}
        </p>
        <div className="label mt-12 flex flex-wrap items-center gap-x-8 gap-y-3 border-t-2 border-white/30 pt-6 text-white/80">
          {FOOTER.links.map((l) => (
            <a key={l.label} href={l.href} className="underline-offset-4 hover:text-white hover:underline">
              {l.label}
            </a>
          ))}
          <a href={LINKS.ansh} className="underline-offset-4 hover:text-white hover:underline">
            {FOOTER.built}
          </a>
          <span className="sm:ml-auto">{FOOTER.copy}</span>
        </div>
      </div>
    </footer>
  );
}
