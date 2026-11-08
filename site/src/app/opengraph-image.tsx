import { ImageResponse } from "next/og";

export const alt = "emfirge: the harness for AI agents that work on your cloud";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

// Static social card in the site's style: white, ink, one green branch. Built once at `next build`.
export default function OpengraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          background: "#ffffff",
          padding: "72px",
          fontFamily: "sans-serif",
          borderTop: "12px solid #0a7a4b",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
          <svg width="56" height="56" viewBox="0 0 24 24" fill="none" strokeWidth="2.6" strokeLinecap="square">
            <path d="M2.5 15H21.5" stroke="#0b1015" />
            <path d="M9 15C13.5 15 13.5 7 21.5 7" stroke="#0a7a4b" />
          </svg>
          <div style={{ color: "#0b1015", fontSize: 40, fontWeight: 600, letterSpacing: -1 }}>emfirge</div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
          <div
            style={{
              color: "#0b1015",
              fontSize: 76,
              fontWeight: 500,
              lineHeight: 1.06,
              letterSpacing: -2.4,
              maxWidth: 1040,
            }}
          >
            The harness for AI agents that work on your cloud.
          </div>
          <div style={{ color: "rgba(11,16,21,0.6)", fontSize: 30, lineHeight: 1.4, maxWidth: 960 }}>
            A true model of your AWS, a branch for every change, and six checks with no AI inside.
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 14, color: "rgba(11,16,21,0.6)", fontSize: 24 }}>
          <div style={{ width: 12, height: 12, background: "#0a7a4b" }} />
          <div>Read-only AWS access · emfirge.cloud</div>
        </div>
      </div>
    ),
    { ...size },
  );
}
