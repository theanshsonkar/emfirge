// Emfirge's fork mark: a horizontal stroke and a branch curving off it.
export function Mark({ size = 24, trunk = "#0B1015", branch = "#0A7A4B", draw = false }: { size?: number; trunk?: string; branch?: string; draw?: boolean }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true" strokeWidth="2.6" strokeLinecap="square">
      <path d="M2.5 15H21.5" stroke={trunk} pathLength={draw ? 1 : undefined} />
      <path d="M9 15C13.5 15 13.5 7 21.5 7" stroke={branch} pathLength={draw ? 1 : undefined} />
    </svg>
  );
}
