"use client";
import { useLive } from "./useLive";

// Security figure 1: a dot-matrix lock and a one-way arrow. Read flows out of the account; nothing flows in (CSS only, paused offscreen).
const LOCK = ["...#####...", "..##...##..", "..#.....#..", "..#.....#..", "..#.....#..", "###########", "###########", "####...####", "####...####", "#####.#####", "#####.#####", "###########", "###########"];
const P = 5.2;

function RoleWide() {
  const { ref, live } = useLive<SVGSVGElement>();
  return (
    <svg ref={ref} className={`role role-w ${live ? "live" : ""}`} viewBox="0 0 640 200" role="img" aria-label="Read flows out of your AWS account through the role; nothing flows in">
      <rect x="26" y="26" width="168" height="148" fill="none" stroke="rgba(11,16,21,.3)" strokeDasharray="2 4" />
      <text x="40" y="46" className="mt">YOUR AWS ACCOUNT</text>
      {[0, 1, 2, 3, 4, 5].map((i) => <rect key={i} x={44 + (i % 3) * 44} y={70 + Math.floor(i / 3) * 44} width="28" height="28" fill="#fff" stroke="rgba(11,16,21,.28)" />)}
      <g transform="translate(236 62)">
        {LOCK.flatMap((row, r) => [...row].map((c, i) => c === "#" ? <rect key={`${r}-${i}`} x={i * P} y={r * P} width={P - 0.9} height={P - 0.9} fill={r < 5 ? "#0B1015" : "#0A7A4B"} /> : null))}
      </g>
      <text x="226" y="150" className="mt">READ-ONLY ROLE</text>
      {/* read: out */}
      <path d="M318 82 H 430" stroke="rgba(11,16,21,.25)" fill="none" />
      <path d="M424 77 L432 82 L424 87" stroke="#0A7A4B" fill="none" strokeWidth="1.4" />
      {[0, 1, 2, 3].map((i) => <rect key={i} className="fl" style={{ ["--i" as string]: i }} x="318" y="79" width="6" height="6" fill="#0A7A4B" />)}
      <text x="318" y="68" className="mt" style={{ fill: "#0A7A4B" }}>READ</text>
      {/* write: nothing in */}
      <path d="M430 126 H 350" stroke="rgba(196,87,74,.55)" strokeDasharray="3 4" fill="none" />
      <path d="M350 118 V 134" stroke="#C4574A" strokeWidth="2" />
      <text x="350" y="150" className="mt" style={{ fill: "#B5483B" }}>WRITE: NONE</text>
      <rect x="452" y="50" width="162" height="100" fill="none" stroke="rgba(11,16,21,.3)" />
      <text x="466" y="70" className="mt">EMFIRGE ENGINE</text>
      <text x="466" y="92" className="mt" style={{ fill: "rgba(11,16,21,.6)" }}>BRANCH · CHECKS</text>
      <text x="466" y="108" className="mt" style={{ fill: "rgba(11,16,21,.6)" }}>NO AI INSIDE</text>
    </svg>
  );
}

// Phones: the same story top to bottom. Read flows down out of the account through the role; nothing flows up.
function RoleTall() {
  const { ref, live } = useLive<SVGSVGElement>();
  return (
    <svg ref={ref} className={`role role-t ${live ? "live" : ""}`} viewBox="0 0 320 424" role="img" aria-label="Read flows out of your AWS account through the role; nothing flows in">
      <rect x="16.5" y="16.5" width="287" height="92" fill="none" stroke="rgba(11,16,21,.3)" strokeDasharray="2 4" />
      <text x="30" y="38" className="mt">YOUR AWS ACCOUNT</text>
      {[0, 1, 2, 3, 4, 5].map((i) => <rect key={i} x={36 + i * 42} y="56" width="28" height="28" fill="#fff" stroke="rgba(11,16,21,.28)" />)}
      <g transform="translate(131 142)">
        {LOCK.flatMap((row, r) => [...row].map((c, i) => c === "#" ? <rect key={`${r}-${i}`} x={i * P} y={r * P} width={P - 0.9} height={P - 0.9} fill={r < 5 ? "#0B1015" : "#0A7A4B"} /> : null))}
      </g>
      <text x="160" y="230" textAnchor="middle" className="mt">READ-ONLY ROLE</text>
      {/* read: down */}
      <path d="M252 112 V 296" stroke="rgba(11,16,21,.25)" fill="none" />
      <path d="M247 290 L252 298 L257 290" stroke="#0A7A4B" fill="none" strokeWidth="1.4" />
      {[0, 1, 2, 3].map((i) => <rect key={i} className="fl" style={{ ["--i" as string]: i }} x="249" y="112" width="6" height="6" fill="#0A7A4B" />)}
      <text x="264" y="140" className="mt" style={{ fill: "#0A7A4B" }}>READ</text>
      {/* write: nothing up */}
      <path d="M52 296 V 116" stroke="rgba(196,87,74,.55)" strokeDasharray="3 4" fill="none" />
      <path d="M44 262 H 60" stroke="#C4574A" strokeWidth="2" />
      <text x="68" y="266" className="mt" style={{ fill: "#B5483B" }}>WRITE: NONE</text>
      <rect x="16.5" y="300.5" width="287" height="104" fill="none" stroke="rgba(11,16,21,.3)" />
      <text x="32" y="326" className="mt">EMFIRGE ENGINE</text>
      <text x="32" y="352" className="mt" style={{ fill: "rgba(11,16,21,.6)" }}>BRANCH · CHECKS</text>
      <text x="32" y="372" className="mt" style={{ fill: "rgba(11,16,21,.6)" }}>NO AI INSIDE</text>
    </svg>
  );
}

export function RoleFig() {
  return (<><RoleWide /><RoleTall /></>);
}
export default RoleFig;
