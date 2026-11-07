import { cn } from "@/lib/cn";

/** Mono card with a title bar. */
export function CodeCard({
  title,
  className,
  children,
}: {
  title: string;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={cn("overflow-hidden rounded-[14px] border border-line bg-surface", className)}>
      <div className="flex items-center gap-2 border-b border-line px-4 py-3">
        <span className="size-3 rounded-full bg-line" />
        <span className="size-3 rounded-full bg-line" />
        <span className="size-3 rounded-full bg-line" />
        <span className="ml-3 truncate font-mono text-xs text-muted">{title}</span>
      </div>
      <div className="px-5 py-5 font-mono text-[13px] leading-[1.7] sm:text-sm">{children}</div>
    </div>
  );
}
