/** The crash-test target: four quadrants, yellow and black. The brand's only symbol. */
export function TestMark({ size = 24, className }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" className={className} aria-hidden="true">
      <path d="M16 16V1A15 15 0 0 0 1 16Z" fill="#FFD60A" />
      <path d="M16 16h15A15 15 0 0 0 16 1Z" fill="#000" />
      <path d="M16 16v15A15 15 0 0 0 31 16Z" fill="#FFD60A" />
      <path d="M16 16H1a15 15 0 0 0 15 15Z" fill="#000" />
      <circle cx="16" cy="16" r="15" fill="none" stroke="#000" strokeWidth="2" />
    </svg>
  );
}
