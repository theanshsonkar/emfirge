import { ImageResponse } from "next/og";

export const alt = "Emfirge — Git branch for your cloud";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

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
          background: "#0b0b0b",
          padding: "72px",
          fontFamily: "sans-serif",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
          <div
            style={{
              width: 56,
              height: 56,
              borderRadius: 14,
              background: "#f5f5f5",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <svg
              width="36"
              height="36"
              viewBox="0 0 32 32"
              fill="none"
              aria-hidden="true"
            >
              <g
                fill="none"
                stroke="#0b0b0b"
                strokeWidth="2"
                strokeLinejoin="round"
                strokeLinecap="round"
              >
                <path d="M16 5 L26.5 11 L26.5 21 L16 27 L5.5 21 L5.5 11 Z" />
                <path d="M26.5 11 L16 16.5 L5.5 11 M16 16.5 L16 27" />
              </g>
              <circle cx="16" cy="10.5" r="2" fill="#22c55e" />
            </svg>
          </div>
          <div
            style={{
              color: "#f5f5f5",
              fontSize: 30,
              fontWeight: 600,
              letterSpacing: -0.5,
            }}
          >
            emfirge
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 22 }}>
          <div
            style={{
              color: "#fafafa",
              fontSize: 72,
              fontWeight: 700,
              lineHeight: 1.05,
              letterSpacing: -1.8,
              maxWidth: 1020,
            }}
          >
            Git branch for your cloud.
          </div>
          <div
            style={{
              color: "#a3a3a3",
              fontSize: 30,
              maxWidth: 920,
              lineHeight: 1.4,
            }}
          >
            Let your AI test AWS security changes before anything touches production.
          </div>
        </div>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 14,
            color: "#d4d4d4",
            fontSize: 24,
          }}
        >
          <div
            style={{
              width: 12,
              height: 12,
              borderRadius: 12,
              background: "#22c55e",
            }}
          />
          <div>Read-only AWS access · No production changes</div>
        </div>
      </div>
    ),
    { ...size },
  );
}
