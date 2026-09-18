/** Emfirge's custom E mark: one continuous, rounded white ribbon. */
export function EmfirgeMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} fill="none" aria-hidden="true">
      <path d="M24.5 7.5H12.25A5.25 5.25 0 0 0 7 12.75v6.5a5.25 5.25 0 0 0 5.25 5.25H24.5M7.5 16h11.25" stroke="currentColor" strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
