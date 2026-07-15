/**
 * EmfirgeMark — the brand glyph.
 *
 * An isometric container (cube): three visible faces meeting at a front edge,
 * with a single green marker on the top face for the brand's one-signal accent.
 * Reads as "your infrastructure, boxed" and stays crisp at favicon sizes.
 *
 * Uses `currentColor` for the container so it inherits its surroundings (e.g.
 * the primary-colored chip in the topbar), and `var(--safe)` for the accent so
 * the green reads in both light and dark themes.
 */
export function EmfirgeMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="none" aria-hidden="true">
      <path
        d="M12 3.5 L20 8 L20 16 L12 20.5 L4 16 L4 8 Z"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path
        d="M20 8 L12 12.5 L4 8 M12 12.5 L12 20.5"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
      <circle cx="12" cy="8" r="1.5" fill="var(--safe)" />
    </svg>
  );
}
