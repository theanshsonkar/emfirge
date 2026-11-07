import { cn } from "@/lib/cn";

/** Content between vertical hairlines (desktop). Sections around it supply the full-bleed rules. */
export function Frame({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn("mx-auto w-full max-w-[1200px] lg:border-x lg:border-line", className)}>{children}</div>;
}
