import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { ImageResponse } from "next/og";
import { SITE } from "@/content";

export const dynamic = "force-static";
export const alt = SITE.ogAlt;
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

/**
 * Archivo (expanded, 800) is bundled in src/assets so the build never needs the network.
 * If the file can't be read, Satori's default sans is used instead.
 */
async function archivo() {
  try {
    return await readFile(join(process.cwd(), "src/assets/Archivo-Expanded-800.ttf"));
  } catch {
    return null;
  }
}

const RED = "#E5341D";

export default async function Image() {
  const font = await archivo();
  const family = font ? "Archivo" : "sans-serif";
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          background: "#fff",
          color: "#000",
          padding: "64px 72px",
          fontFamily: family,
          fontWeight: 800,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
          <svg width="84" height="84" viewBox="0 0 32 32">
            <path d="M16 16V1A15 15 0 0 0 1 16Z" fill="#FFD60A" />
            <path d="M16 16h15A15 15 0 0 0 16 1Z" fill="#000" />
            <path d="M16 16v15A15 15 0 0 0 31 16Z" fill="#FFD60A" />
            <path d="M16 16H1a15 15 0 0 0 15 15Z" fill="#000" />
            <circle cx="16" cy="16" r="15" fill="none" stroke="#000" strokeWidth="2" />
          </svg>
          <div style={{ fontSize: 40, letterSpacing: -0.5 }}>emfirge</div>
        </div>

        <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between" }}>
          <div style={{ display: "flex", flexDirection: "column", fontSize: 128, lineHeight: 1, letterSpacing: -3 }}>
            <div>Go on.</div>
            <div>Break it.</div>
          </div>
          <div
            style={{
              display: "flex",
              transform: "rotate(-7deg)",
              border: `10px solid ${RED}`,
              borderRadius: 18,
              padding: 6,
              marginBottom: 24, marginRight: 36,
            }}
          >
            <div
              style={{
                display: "flex",
                border: `3px solid ${RED}`,
                borderRadius: 10,
                padding: "6px 24px",
                color: RED,
                fontSize: 52,
                letterSpacing: 1,
              }}
            >
              BLOCKED
            </div>
          </div>
        </div>

        <div style={{ display: "flex", fontSize: 30, color: "#4A4A4A" }}>emfirge.cloud</div>
      </div>
    ),
    {
      ...size,
      fonts: font ? [{ name: "Archivo", data: font, weight: 800, style: "normal" }] : undefined,
    },
  );
}
