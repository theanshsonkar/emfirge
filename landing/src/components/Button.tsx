import { cn } from "@/lib/cn";

type Variant = "primary" | "outline" | "dark-outline";

const styles: Record<Variant, string> = {
  primary: "bg-brand text-white border border-brand hover:bg-brand-hover hover:border-brand-hover",
  outline: "bg-white text-ink border border-ink hover:bg-paper",
  "dark-outline": "bg-transparent text-mist border border-trunk hover:bg-forest-line",
};

export function Button({
  href,
  variant = "primary",
  children,
  className,
}: {
  href: string;
  variant?: Variant;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <a
      href={href}
      className={cn(
        "inline-flex items-center justify-center rounded-[4px] px-3.5 py-2 text-sm font-medium leading-5 transition-colors",
        styles[variant],
        className,
      )}
    >
      {children}
    </a>
  );
}
