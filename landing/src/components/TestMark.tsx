/** The crash-test target: four quadrants, yellow and black. The brand's only symbol. `ring` adds a white outline for dark backgrounds. */
export function TestMark({ size = 24, className, ring }: { size?: number; className?: string; ring?: boolean }) {
  const edge = ring ? "#fff" : "#000";
  return (
    <svg
      width={size}
      height={size}
      viewBox={ring ? "-3 -3 38 38" : "0 0 32 32"}
      className={className}
      aria-hidden="true"
    >
      <path d="M16 16V1A15 15 0 0 0 1 16Z" fill="#FFD60A" />
      <path d="M16 16h15A15 15 0 0 0 16 1Z" fill="#000" />
      <path d="M16 16v15A15 15 0 0 0 31 16Z" fill="#FFD60A" />
      <path d="M16 16H1a15 15 0 0 0 15 15Z" fill="#000" />
      {ring ? <path d="M16 1V31M1 16H31" stroke="#fff" strokeWidth="1.2" /> : null}
      <circle cx="16" cy="16" r="15" fill="none" stroke={edge} strokeWidth={ring ? 2.4 : 2} />
    </svg>
  );
}
