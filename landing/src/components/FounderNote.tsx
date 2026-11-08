import { NOTE } from "@/content";

/** A hand-drawn signature path, not a font. */
function Signature() {
  return (
    <svg viewBox="0 0 150 56" className="h-14 w-[150px]" role="img" aria-label={NOTE.signedAs}>
      <path
        d="M6 44 C14 30 24 10 31 8 C35 7 33 18 28 30 C24 40 22 46 28 44 M20 31 C30 28 40 26 48 25 M52 40 C54 30 60 24 63 28 C65 31 58 40 62 41 C68 42 72 30 78 29 C82 29 80 38 85 38 C91 38 94 28 99 27 C103 27 101 37 107 37 C113 37 118 30 122 24 M60 49 C80 46 110 47 142 44"
        fill="none"
        stroke="#000"
        strokeWidth="2.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function FounderNote() {
  return (
    <section id="why" aria-labelledby="why-h" className="mx-auto max-w-[1320px] px-4 py-16 sm:px-8 lg:py-24">
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
