import { cn } from "@/lib/cn";
import { Container } from "./Container";
import { Reveal } from "./Reveal";

export function Section({
  id,
  tone = "ink",
  className,
  children,
  "aria-label": ariaLabel,
  "aria-labelledby": labelledBy,
  reveal = true,
}: {
  id?: string;
  tone?: "ink" | "paper";
  className?: string;
  children: React.ReactNode;
  "aria-label"?: string;
  "aria-labelledby"?: string;
  reveal?: boolean;
}) {
  return (
    <section
      id={id}
      aria-label={ariaLabel}
      aria-labelledby={labelledBy}
      className={cn("py-20 md:py-28", tone === "paper" && "bg-paper text-ink", className)}
    >
      <Container>
        {reveal ? <Reveal>{children}</Reveal> : children}
      </Container>
    </section>
  );
}

export function Eyebrow({ className, ...props }: React.ComponentProps<"p">) {
  return (
    <p
      className={cn("mb-4 font-mono text-xs uppercase tracking-[0.12em] text-forge", className)}
      {...props}
    />
  );
}

export function H2({ className, ...props }: React.ComponentProps<"h2">) {
  return (
    <h2
      className={cn(
        "font-display text-[clamp(34px,5.2vw,60px)] leading-[1.04] tracking-[-0.02em] text-balance [&_em]:text-forge",
        className,
      )}
      {...props}
    />
  );
}
