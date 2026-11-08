"use client";
import { Mark } from "./Mark";
import { useLive } from "./useLive";

// Figure 3: five inputs converge on one branch, which leads to one verdict. A comet runs each line in turn (CSS only, paused offscreen).
const INPUTS = ["Typed", "AWS CLI", "AWS API", "Terraform", "CloudFormation"];
const Y = [28, 70, 112, 154, 196];
const path = (i: number) => `M146 ${Y[i]} C 224 ${Y[i]}, 236 112, 306 112`;

export function WaysFig() {
  const { ref, live } = useLive<SVGSVGElement>();
  return (
    <svg ref={ref} className={`ways ${live ? "live" : ""}`} viewBox="0 0 640 224" role="img" aria-label="Five input formats converge on one branch and produce one verdict">
      {INPUTS.map((l, i) => (
        <g key={l}>
          <path d={path(i)} fill="none" stroke="rgba(11,16,21,.22)" strokeWidth="1" />
          <path className="cm" style={{ ["--i" as string]: i }} d={path(i)} pathLength={1} fill="none" strokeWidth="2.2" />
          <rect className="tl" style={{ ["--i" as string]: i }} x="26" y={Y[i] - 15} width="120" height="30" fill="#fff" strokeWidth="1" />
          <text x="40" y={Y[i] + 3.5} className="mt">{l.toUpperCase()}</text>
        </g>
      ))}
      <path d="M402 112 H 508" stroke="rgba(11,16,21,.22)" fill="none" />
      <path className="cm out" d="M402 112 H 508" pathLength={1} fill="none" strokeWidth="2.2" />
      <rect x="306" y="84" width="96" height="56" fill="#0A7A4B" />
      <g transform="translate(316 100)"><Mark size={24} trunk="#fff" branch="#fff" /></g>
      <text x="346" y="116" className="mt" fill="#fff" style={{ fill: "#fff" }}>BRANCH</text>
      <rect className="vd" x="508" y="102" width="20" height="20" fill="#0A7A4B" />
      <text x="548" y="116" className="mt">ONE VERDICT</text>
      <text x="548" y="130" className="mt" style={{ fill: "rgba(11,16,21,.45)" }}>L18 L19 L21</text>
    </svg>
  );
}
export default WaysFig;
