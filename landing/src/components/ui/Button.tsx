import { cn } from "@/lib/cn";

export function ButtonLink({
  variant = "primary",
  className,
  ...props
}: React.ComponentProps<"a"> & { variant?: "primary" | "ghost" }) {
  return (
    <a
      className={cn(
        "inline-flex h-12 items-center justify-center gap-2 whitespace-nowrap rounded-xl px-5 text-[15px] font-semibold transition-all",
        variant === "primary" &&
          "bg-forge text-ink shadow-[0_0_0_1px_rgba(255,255,255,0.18)_inset,0_8px_30px_-8px_rgba(255,90,31,0.7)] hover:bg-forge-hover",
        variant === "ghost" &&
          "glass border border-white/10 text-paper hover:border-white/25 hover:bg-white/[0.06]",
        className,
      )}
      {...props}
    />
  );
}
