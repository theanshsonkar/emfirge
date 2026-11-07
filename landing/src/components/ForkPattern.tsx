/** Faint branch-fork glyphs scattered over the hero area, fading out downward. */
const GLYPHS: [number, number, number, number][] = [
  // x, y, scale, rotate
  [30, 24, 1.9, -10],
  [190, 60, 1.3, 14],
  [300, 20, 1.6, 6],
  [90, 150, 1.4, 18],
  [230, 190, 2, -14],
  [330, 140, 1.2, 8],
  [20, 280, 1.5, -6],
  [150, 300, 1.2, 12],
  [290, 310, 1.7, -18],
];

export function ForkPattern() {
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none absolute inset-x-0 top-0 h-[900px] overflow-hidden"
      style={{ maskImage: "linear-gradient(to bottom, #000 0%, #000 35%, transparent 100%)" }}
    >
      <svg width="100%" height="100%" className="text-black opacity-[0.1]">
        <defs>
          <pattern id="forks" width="380" height="380" patternUnits="userSpaceOnUse">
            {GLYPHS.map(([x, y, s, r], i) => (
              <g key={i} transform={`translate(${x} ${y}) rotate(${r} 7 7) scale(${s})`}>
                <path
                  d="M4 14V1.5M4 10.5C4 6.5 10 8 10 3.5"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.3"
                  strokeLinecap="round"
                />
                <circle cx="4" cy="1.5" r="1.3" fill="currentColor" />
                <circle cx="10" cy="3.5" r="1.3" fill="currentColor" />
              </g>
            ))}
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#forks)" />
      </svg>
    </div>
  );
}
