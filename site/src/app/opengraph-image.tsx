import { ImageResponse } from "next/og";

export const alt = "Emfirge: Fork your cloud. Prove the change. Then apply.";
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
            <svg width="34" height="34" viewBox="0 0 32 32" fill="none" stroke="#0b0b0b" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="11" cy="9" r="2.6" />
              <circle cx="11" cy="23" r="2.6" />
              <circle cx="21" cy="14" r="2.6" />
              <path d="M11 11.6v8.8" />
              <path d="M11 15.5c0 3 2 4 5 4" />
            </svg>
          </div>
          <div style={{ color: "#f5f5f5", fontSize: 30, fontWeight: 600, letterSpacing: -0.5 }}>
            emfirge
          </div>
          <div
            style={{
              marginLeft: 8,
              padding: "4px 12px",
              border: "1px solid #333",
              borderRadius: 8,
              color: "#8a8a8a",
              fontSize: 18,
              letterSpacing: 2,
            }}
          >
            DOCS
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
          <div style={{ color: "#fafafa", fontSize: 64, fontWeight: 700, lineHeight: 1.05, letterSpacing: -1.5, maxWidth: 900 }}>
            Fork your cloud. Prove the change. Then apply.
          </div>
          <div style={{ color: "#9a9a9a", fontSize: 28, maxWidth: 860, lineHeight: 1.4 }}>
            A read-only MCP that clones your AWS graph, re-runs 58 rules, and shows the risk delta before you touch prod.
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 14, color: "#22c55e", fontSize: 24 }}>
          <div style={{ width: 12, height: 12, borderRadius: 12, background: "#22c55e" }} />
          <div style={{ color: "#c8c8c8" }}>7 MCP tools · deterministic · read-only</div>
        </div>
      </div>
    ),
    { ...size },
  );
}
