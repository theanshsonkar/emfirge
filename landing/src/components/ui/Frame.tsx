import { cn } from "@/lib/cn";

/**
 * A panel with a 1px gradient border. `hover` swaps the hairline for a forge-orange
 * gradient; `tone="forge"` keeps it lit.
 */
export function Frame({
  children,
  className,
  innerClassName,
  radius = 16,
  hover = false,
  tone = "soft",
}: {
  children: React.ReactNode;
  className?: string;
  innerClassName?: string;
  radius?: number;
  hover?: boolean;
  tone?: "soft" | "forge";
}) {
  return (
    <div className={cn("group/frame relative", className)} style={{ borderRadius: radius }}>
      <div
        aria-hidden="true"
        className="absolute inset-0"
        style={{
          borderRadius: radius,
          background:
            "linear-gradient(145deg, rgba(255,255,255,0.20), rgba(255,255,255,0.05) 32%, rgba(255,255,255,0.04) 68%, rgba(255,255,255,0.12))",
        }}
      />
      <div
        aria-hidden="true"
        className={cn(
          "absolute inset-0 transition-opacity duration-300",
          tone === "forge" ? "opacity-100" : "opacity-0",
          hover && "group-hover/frame:opacity-100",
        )}
        style={{
          borderRadius: radius,
          background:
            "linear-gradient(145deg, rgba(255,90,31,0.75), rgba(255,90,31,0.12) 38%, rgba(120,60,150,0.25) 72%, rgba(255,90,31,0.4))",
        }}
      />
      <div
        className={cn("relative m-px overflow-hidden bg-[#0e0e10]", innerClassName)}
        style={{ borderRadius: radius - 1 }}
      >
        {children}
      </div>
    </div>
  );
}
