import { OWNER, VERDICT, type OwnerDecision, type Verdict } from "@/content";
import { cn } from "@/lib/cn";

const INK: Record<Verdict, { ink: string; plate?: string; size: number }> = {
  blocked: { ink: "#E5341D", size: 36 },
  passed: { ink: "#1F9D55", size: 36 },
  ask: { ink: "#000000", plate: "#FFD60A", size: 29 },
};

/** A rubber stamp. The ink filter (feTurbulence + feDisplacementMap) lives in LabDefs and is used here only. */
export function Stamp({ verdict, animate, className }: { verdict: Verdict; animate?: boolean; className?: string }) {
  const { ink, plate, size } = INK[verdict];
  const word = VERDICT[verdict].stamp;
  return (
    <svg
      viewBox="0 0 224 76"
      role="img"
      aria-label={`Stamp: ${word}`}
      className={cn("block h-auto w-[190px] origin-center mix-blend-multiply sm:w-[212px]", animate ? "stamp-thump" : "-rotate-[7deg]", className)}
    >
      <g filter="url(#ink)" fill="none" stroke={ink}>
        {plate ? <rect x="4" y="4" width="216" height="68" rx="9" fill={plate} stroke="none" /> : null}
        <rect x="4" y="4" width="216" height="68" rx="9" strokeWidth="4.5" />
        <rect x="11" y="11" width="202" height="54" rx="5" strokeWidth="1.6" />
        <text
          x="112"
          y="51"
          textAnchor="middle"
          fill={ink}
          stroke="none"
          fontSize={size}
          textLength="176"
          lengthAdjust="spacingAndGlyphs"
          style={{ fontFamily: "var(--font-archivo), system-ui, sans-serif", fontWeight: 800, fontVariationSettings: '"wdth" 125' }}
        >
          {word}
        </text>
      </g>
    </svg>
  );
}

/** The owner's second stamp: smaller, black ink, tilted the other way. It lands overlapping the verdict stamp. */
export function DecisionStamp({ decision, animate, className }: { decision: OwnerDecision; animate?: boolean; className?: string }) {
  const word = OWNER[decision === "approved" ? "approve" : "deny"].stamp;
  return (
    <svg
      viewBox="0 0 224 52"
      role="img"
      aria-label={`Stamp: ${word}`}
      className={cn("block h-auto w-[150px] origin-center mix-blend-multiply sm:w-[164px]", animate ? "stamp-thump-b" : "rotate-[4deg]", className)}
    >
      <g filter="url(#ink)" fill="none" stroke="#000">
        <rect x="4" y="4" width="216" height="44" rx="7" strokeWidth="4" />
        <rect x="10" y="10" width="204" height="32" rx="4" strokeWidth="1.4" />
        <text
          x="112"
          y="35"
          textAnchor="middle"
          fill="#000"
          stroke="none"
          fontSize="19"
          textLength="184"
          lengthAdjust="spacingAndGlyphs"
          style={{ fontFamily: "var(--font-archivo), system-ui, sans-serif", fontWeight: 800, fontVariationSettings: '"wdth" 125' }}
        >
          {word}
        </text>
      </g>
    </svg>
  );
}
