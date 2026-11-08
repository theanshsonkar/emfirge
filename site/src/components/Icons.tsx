export function Ext({ size = 9 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.1" aria-hidden="true">
      <path d="M2 8L8 2M3.5 2H8V6.5" />
    </svg>
  );
}
export function Copy() {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.1" aria-hidden="true">
      <rect x="4.5" y="4.5" width="7" height="7" /><path d="M9.5 4.5V2.5H2.5V9.5H4.5" />
    </svg>
  );
}
export function Caret() {
  return (<svg width="9" height="9" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.2" aria-hidden="true"><path d="M2 3.5L5 6.5L8 3.5" /></svg>);
}
export function Check() {
  return (<svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.3" aria-hidden="true"><path d="M3 7.5L6 10.5L11 4" /></svg>);
}
