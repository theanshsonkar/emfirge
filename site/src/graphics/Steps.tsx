// Set up figure (the /quickstart/ route): the four steps a person takes, as small square tiles joined by a thin line. Each fills green in turn once, when revealed (pure CSS, see .steps).
const ICONS = [
  <path key="a" d="M4 7l5 5-5 5M12 18h8" />, // paste the prompt: a prompt
  <g key="b"><circle cx="12" cy="8.5" r="3.5" /><path d="M5 20c1-4 4-5.5 7-5.5s6 1.5 7 5.5" /></g>, // approve sign-in: a person
  <g key="c"><rect x="6" y="11" width="12" height="9" /><path d="M9 11V8a3 3 0 016 0v3" /></g>, // create the role: a lock
  <path key="d" d="M5 12.5l4.5 4.5L19 7" />, // ask as usual
];
const LABELS = ["Paste the prompt", "Approve sign-in", "Create the role", "Ask as usual"];

export default function Steps() {
  return (
    <ol className="steps">
      {LABELS.map((l, i) => (
        <li key={l} style={{ ["--i" as string]: i }}>
          <span className="stile"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" aria-hidden="true">{ICONS[i]}</svg></span>
          <span className="label"><b>{i + 1}</b> {l}</span>
        </li>
      ))}
    </ol>
  );
}
