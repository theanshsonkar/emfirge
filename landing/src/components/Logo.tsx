export function LogoMark({ size = 22, className }: { size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="10.25 6.5 25 25"
      fill="none"
      aria-hidden="true"
      className={className}
    >
      <path
        d="M31.5 10.5H19.25A5.25 5.25 0 0 0 14 15.75v6.5a5.25 5.25 0 0 0 5.25 5.25H31.5M14.5 19h11.25"
        stroke="currentColor"
        strokeWidth="4.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
