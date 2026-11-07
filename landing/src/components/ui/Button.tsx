import { cn } from "@/lib/cn";

export function ButtonLink({
  variant = "primary",
  className,
  ...props
}: React.ComponentProps<"a"> & { variant?: "primary" | "ghost" }) {
  return (
    <a
      className={cn(
        "inline-flex h-11 items-center justify-center gap-2 whitespace-nowrap rounded-[10px] px-5 text-[15px] font-semibold transition-colors",
        variant === "primary" && "bg-forge text-ink hover:bg-forge-hover",
        variant === "ghost" && "border border-line text-paper hover:border-muted",
        className,
      )}
      {...props}
    />
  );
}
