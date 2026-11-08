import { NOTE } from "@/content";

/** A hand-drawn signature path, not a font. */
function Signature() {
  return (
    <svg viewBox="0 0 170 64" className="h-16 w-[170px]" role="img" aria-label={NOTE.signedAs}>
      <path
        d="M6 50 C12 38 20 14 27 9 C32 6 32 28 40 46 C42 50 46 48 48 42 M15 36 C26 32 40 31 52 33 M50 48 C50 38 52 31 54 30 C56 33 54 42 56 47 C58 38 64 29 69 31 C73 33 70 44 72 48 C76 46 79 40 81 34 C82 30 85 30 84 33 C82 37 90 38 90 43 C90 49 84 50 83 46 M92 47 C96 34 99 16 103 9 C107 6 105 30 100 44 C99 48 102 48 105 44 C108 36 114 31 118 34 C121 38 114 46 118 48 C122 49 126 45 130 40"
        fill="none"
        stroke="#000"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path d="M10 58 C50 53 100 57 150 50" fill="none" stroke="#000" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}

export function FounderNote() {
  return (
    <section id="why" aria-labelledby="why-h" className="mx-auto max-w-[1440px] px-4 py-16 sm:px-8 lg:py-24">
      <h2 id="why-h" className="display text-[32px] sm:text-[40px]">
        {NOTE.title}
      </h2>
      <div className="mt-8 max-w-[60ch] space-y-5">
        {NOTE.paragraphs.map((p) => (
          <p key={p.slice(0, 16)}>{p}</p>
        ))}
        <Signature />
      </div>
    </section>
  );
}
