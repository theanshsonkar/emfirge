import { cn } from "@/lib/cn";

/** Lowercase section heading. `*word*` becomes the one italic word. */
export function H2({ children, className }: { children: string; className?: string }) {
  const parts = children.split(/\*([^*]+)\*/g);
  return (
    <h2
      className={cn(
        "text-balance text-center text-[28px] font-semibold leading-[1.15] tracking-[-0.03em] text-ink md:text-[32px]",
        className,
      )}
    >
      {parts.map((p, i) => (i % 2 ? <em key={i}>{p}</em> : p))}
    </h2>
  );
}
