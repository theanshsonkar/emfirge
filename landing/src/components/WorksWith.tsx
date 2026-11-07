import { AGENTS } from "@/content";

function Diamond() {
  return <span aria-hidden="true" className="mx-7 inline-block size-1.5 rotate-45 bg-forge" />;
}

export function WorksWith() {
  return (
    <section aria-label="Compatible agents" className="border-y border-white/[0.07] py-9">
      <p className="text-center font-mono text-xs uppercase tracking-[0.14em] text-muted">
        Works with any agent that runs a shell
      </p>
      <div className="mt-6 overflow-hidden [mask-image:linear-gradient(to_right,transparent,#000_12%,#000_88%,transparent)]">
        <ul className="marquee-track flex w-max animate-marquee items-center whitespace-nowrap font-display text-[28px] text-paper/90 md:text-[34px]">
          {[0, 1].map((dup) =>
            AGENTS.map((a) => (
              <li key={`${dup}-${a}`} className="flex items-center" aria-hidden={dup === 1 || undefined}>
                {a}
                <Diamond />
              </li>
            )),
          )}
        </ul>
      </div>
    </section>
  );
}
