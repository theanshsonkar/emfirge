import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { ImageResponse } from "next/og";
import { deltaPngDataUrl } from "./_og/delta";

export const alt = "emfirge: the harness for AI agents that work on your cloud. Every change tried on a branch first.";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

const TEXT = "#F2F7F4";
const font = (f: string) => readFile(join(process.cwd(), "src/app/_og", f));

// Static social card (1200x630, built once at `next build`): the hero's river delta full-bleed, a dark gradient on the
// left so the headline reads at thumbnail size, and the delta fully lit on the right.
export default async function OpengraphImage() {
  const [g400, g500, m500] = await Promise.all([font("Geist-400.ttf"), font("Geist-500.ttf"), font("GeistMono-500.ttf")]);
  const bg = deltaPngDataUrl({
    w: size.width, h: size.height, cell: 6, scale: (size.width / 640) * 1.05, x0: -10, y0: -15,
    field: "#0B3B2A", lo: "#2E8F64", hi: "#B9EBD2",
    overlay: [{ stop: 0, a: 0.96 }, { stop: 0.42, a: 0.88 }, { stop: 0.75, a: 0.2 }, { stop: 1, a: 0 }],
    overlayRgb: [6, 30, 22],
    changes: [
      { path: "A1", f: 0.22 }, { path: "A1", f: 0.52 }, { path: "A1", f: 0.8 }, { path: "B1", f: 0.62, red: true }, { path: "B2", f: 0.86 },
    ],
  });
  return new ImageResponse(
    (
      <div style={{ width: "100%", height: "100%", display: "flex", position: "relative", background: "#0B3B2A", fontFamily: "Geist", color: TEXT }}>
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src={bg} width={size.width} height={size.height} alt="" style={{ position: "absolute", left: 0, top: 0 }} />
        <div style={{ position: "absolute", left: 72, top: 64, bottom: 64, width: 640, display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" strokeWidth="2.8" strokeLinecap="square">
              <path d="M2.5 15H21.5" stroke={TEXT} />
              <path d="M9 15C13.5 15 13.5 7 21.5 7" stroke="#1FA36B" />
            </svg>
            <div style={{ fontSize: 34, fontWeight: 500, letterSpacing: -0.8 }}>emfirge</div>
          </div>
          <div style={{ display: "flex", flexDirection: "column" }}>
            <div style={{ fontSize: 64, fontWeight: 500, lineHeight: 1.05, letterSpacing: -2.5 }}>The harness for AI agents that work on your cloud.</div>
            <div style={{ marginTop: 22, fontSize: 28, fontWeight: 400, letterSpacing: -0.2, color: "rgba(242,247,244,0.72)" }}>Every change tried on a branch first.</div>
          </div>
          <div style={{ fontFamily: "Geist Mono", fontSize: 18, fontWeight: 500, letterSpacing: "0.06em", color: "rgba(242,247,244,0.7)" }}>EMFIRGE.CLOUD</div>
        </div>
      </div>
    ),
    {
      ...size,
      fonts: [
        { name: "Geist", data: g400, weight: 400, style: "normal" },
        { name: "Geist", data: g500, weight: 500, style: "normal" },
        { name: "Geist Mono", data: m500, weight: 500, style: "normal" },
      ],
    },
  );
}
