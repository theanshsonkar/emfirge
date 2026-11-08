/** Shared SVG defs: rubber-stamp ink, damage hatches, arrowheads. Rendered once. */
export function LabDefs() {
  return (
    <svg width="0" height="0" className="absolute" aria-hidden="true" focusable="false">
      <defs>
        {/* Rubber ink: warped edges, then uneven coverage. Used by the stamp only. */}
        <filter id="ink" x="-6%" y="-10%" width="112%" height="120%">
          <feTurbulence type="fractalNoise" baseFrequency="0.045" numOctaves="2" seed="4" result="warp" />
          <feDisplacementMap in="SourceGraphic" in2="warp" scale="3.5" xChannelSelector="R" yChannelSelector="G" result="rough" />
          <feTurbulence type="fractalNoise" baseFrequency="0.8" numOctaves="2" seed="11" result="grain" />
          <feColorMatrix
            in="grain"
            type="matrix"
            values="0 0 0 0 0  0 0 0 0 0  0 0 0 0 0  5 0 0 0 -1.35"
            result="coverage"
          />
          <feComposite in="rough" in2="coverage" operator="in" />
        </filter>
        <pattern id="hatch-red" width="7" height="7" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
          <rect width="7" height="7" fill="#fff" />
          <rect width="2.6" height="7" fill="#E5341D" />
        </pattern>
        <pattern id="hatch-yellow" width="7" height="7" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
          <rect width="7" height="7" fill="#fff" />
          <rect width="3.4" height="7" fill="#FFD60A" />
        </pattern>
        <marker id="arrow-ink" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">
          <path d="M0 1 L10 5 L0 9 Z" fill="#000" />
        </marker>
        <marker id="arrow-red" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">
          <path d="M0 1 L10 5 L0 9 Z" fill="#E5341D" />
        </marker>
        <marker id="arrow-ghost" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">
          <path d="M0 1 L10 5 L0 9 Z" fill="#8A8A8A" />
        </marker>
      </defs>
    </svg>
  );
}
