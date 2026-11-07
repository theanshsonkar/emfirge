import { cn } from "@/lib/cn";
import { CodeCard } from "./CodeCard";

export function SignalCard({
  status,
  title,
  lines,
  className,
}: {
  status: "FAIL" | "PASS" | "BLOCK";
  title: string;
  lines: string[];
  className?: string;
}) {
  return (
    <CodeCard title="signal" className={className}>
      <p>
        <span className={cn("font-bold", status === "PASS" ? "text-pass" : "text-block")}>{status}</span>{" "}
        <span className="text-paper">{title}</span>
      </p>
      {lines.map((l) => (
        <p key={l} className="break-words text-muted">{l}</p>
      ))}
    </CodeCard>
  );
}
