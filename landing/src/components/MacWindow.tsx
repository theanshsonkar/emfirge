import { cn } from "@/lib/cn";

export function TrafficLights({ className }: { className?: string }) {
  const dot = "h-3 w-3 rounded-full shadow-[inset_0_0_0_0.5px_rgba(0,0,0,0.14)]";
  return (
    <div className={cn("flex items-center gap-2", className)} aria-hidden="true">
      <span className={cn(dot, "bg-tl-red")} />
      <span className={cn(dot, "bg-tl-yellow")} />
      <span className={cn(dot, "bg-tl-green")} />
    </div>
  );
}

/** A small yellow Notes-style app icon, drawn in CSS-free SVG. */
function NoteGlyph() {
  return (
    <svg width="13" height="13" viewBox="0 0 13 13" aria-hidden="true">
      <rect x="1" y="0.5" width="11" height="12" rx="2.4" fill="#FFD60A" />
      <rect x="1" y="0.5" width="11" height="3.2" rx="1.6" fill="#FFC400" />
      <path d="M3.4 6.2h6.2M3.4 8.3h6.2M3.4 10.4h4" stroke="#fff" strokeOpacity=".85" strokeWidth=".8" strokeLinecap="round" />
    </svg>
  );
}

type Variant = "terminal" | "settings" | "notes";

/**
 * macOS window chrome.
 * terminal: 28px titlebar, title centered.  notes: 32px titlebar with the Notes icon.
 * settings: no titlebar, the lights sit inside the sidebar (children render the layout).
 */
export function MacWindow({
  variant,
  title,
  children,
  className,
  lightsClassName,
}: {
  variant: Variant;
  title?: string;
  children: React.ReactNode;
  className?: string;
  lightsClassName?: string;
}) {
  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-[12px] bg-surface text-left shadow-window",
        className,
      )}
    >
      {variant === "settings" ? (
        <TrafficLights className={cn("absolute left-[18px] top-[19px] z-10", lightsClassName)} />
      ) : (
        <div
          className={cn(
            "relative flex items-center justify-center bg-titlebar shadow-[0_0.5px_0_0_rgba(0,0,0,0.12)]",
            variant === "terminal" ? "h-7" : "h-8",
          )}
        >
          <TrafficLights className="absolute left-3" />
          <div className="flex min-w-0 items-center gap-1.5 px-20 text-[13px] font-medium leading-none text-ink-2">
            {variant === "notes" && <NoteGlyph />}
            <span className="truncate">{title}</span>
          </div>
        </div>
      )}
      {children}
    </div>
  );
}
