import { deflateSync } from "node:zlib";
import { BAYER4, fbm } from "@/graphics/noise";
import { SEGS, at, hex, type PathName } from "@/graphics/deltaGeom";

// The homepage hero delta (graphics/Delta.tsx) rasterised once at build time into a PNG data URL for the share image.
// Same channels (deltaGeom.ts), noise (noise.ts), bank glow, ordered dither, levels and colours as the hero; the only
// differences are a stationary frame, a coarser 6px cell, and a left-to-right dark overlay baked in so text can sit on it.
// Satori has no canvas, and ~8,000 dots would be far too many SVG nodes, so this uses a small dependency-free PNG encoder.
export type DeltaImgOpts = {
  w: number; h: number; cell: number; scale: number; x0: number; y0: number;
  field: string; lo: string; hi: string;
  overlay: { stop: number; a: number }[]; overlayRgb: [number, number, number];
  changes: { path: PathName; f: number; red?: boolean }[];
};

const LEVELS = 7;

export function deltaPngDataUrl(o: DeltaImgOpts): string {
  const { w, h, cell, scale: sc } = o;
  const cols = Math.ceil(w / cell), rows = Math.ceil(h / cell);
  const px = new Float32Array(w * h * 3);
  const field = hex(o.field), lo = hex(o.lo), hi = hex(o.hi);
  for (let i = 0; i < w * h; i++) { px[i * 3] = field[0]; px[i * 3 + 1] = field[1]; px[i * 3 + 2] = field[2]; }

  // Area-coverage antialiased axis-aligned rect with colour c and opacity a, like canvas fillRect.
  const rect = (x: number, y: number, rw: number, rh: number, c: number[], a: number) => {
    const xa = Math.max(0, Math.floor(x)), xb = Math.min(w, Math.ceil(x + rw));
    const ya = Math.max(0, Math.floor(y)), yb = Math.min(h, Math.ceil(y + rh));
    for (let j = ya; j < yb; j++) {
      const cy = Math.min(j + 1, y + rh) - Math.max(j, y);
      for (let i = xa; i < xb; i++) {
        const cov = (Math.min(i + 1, x + rw) - Math.max(i, x)) * cy * a;
        if (cov <= 0) continue;
        const k = (j * w + i) * 3;
        px[k] += (c[0] - px[k]) * cov; px[k + 1] += (c[1] - px[k + 1]) * cov; px[k + 2] += (c[2] - px[k + 2]) * cov;
      }
    }
  };
  const mix = (t: number) => [0, 1, 2].map((n) => lo[n] + (hi[n] - lo[n]) * t);

  const pts: [number, number, number][] = [];
  for (const s of SEGS) s.pts.forEach((p, i, a) => pts.push([p[0], p[1], s.w * (1 - 0.25 * (i / (a.length - 1)))]));
  const buckets: number[][] = Array.from({ length: LEVELS }, () => []);
  const big: number[] = [];
  for (let j = 0; j < rows; j++) for (let i = 0; i < cols; i++) {
    const x = ((i + 0.5) * cell) / sc + o.x0, y = ((j + 0.5) * cell) / sc + o.y0;
    let sd = 1e9;
    for (const p of pts) { const d = Math.hypot(p[0] - x, p[1] - y) - p[2]; if (d < sd) sd = d; }
    if (sd < 0.5) { big.push(i, j); continue; }
    const nx = i * 0.06, ny = j * 0.11;
    let v = 0.1 + 0.55 * fbm(nx, ny, 3, 3) + 0.12 * Math.sin((nx + ny * 0.6) * 3.1 + fbm(nx * 2, ny * 2, 9, 2) * 4);
    const glow = Math.max(0, 1 - sd / 11);
    v = Math.min(1, Math.max(0, v + 0.32 * glow * glow));
    if (v <= BAYER4[(j & 3) * 4 + (i & 3)] * 0.72 + 0.08) continue;
    buckets[Math.min(LEVELS - 1, Math.floor(v * LEVELS))].push(i, j);
  }
  const sz = Math.max(1.2, cell * 0.46);
  buckets.forEach((b, L) => {
    const c = mix((L / (LEVELS - 1)) * 0.55), a = 0.45 + 0.55 * (L / (LEVELS - 1));
    for (let k = 0; k < b.length; k += 2) rect(b[k] * cell + (cell - sz) / 2, b[k + 1] * cell + (cell - sz) / 2, sz, sz, c, a);
  });
  const bs = sz * 1.45, bc = mix(0.95);
  for (let k = 0; k < big.length; k += 2) rect(big[k] * cell + (cell - bs) / 2, big[k + 1] * cell + (cell - bs) / 2, bs, bs, bc, 1);

  // "changes": pale squares along the channels, one red where a channel is blocked (under the overlay, like the dots)
  const S = Math.max(12, 14 * sc * 0.55), E = 1.2;
  for (const ch of o.changes) {
    const p = at(ch.path, ch.f), X = (p[0] - o.x0) * sc - S / 2, Y = (p[1] - o.y0) * sc - S / 2;
    rect(X, Y, S, S, hex(ch.red ? "#C4574A" : "#E9F7EF"), 1);
    const e = hex(ch.red ? "#8f2f26" : "#7fbf9f");
    rect(X, Y, S, E, e, 1); rect(X, Y + S - E, S, E, e, 1); rect(X, Y + E, E, S - 2 * E, e, 1); rect(X + S - E, Y + E, E, S - 2 * E, e, 1);
  }

  // left-to-right overlay
  const ov = (u: number) => {
    const s = o.overlay;
    if (u <= s[0].stop) return s[0].a;
    for (let k = 1; k < s.length; k++) if (u <= s[k].stop) return s[k - 1].a + ((u - s[k - 1].stop) / (s[k].stop - s[k - 1].stop)) * (s[k].a - s[k - 1].a);
    return s[s.length - 1].a;
  };
  for (let i = 0; i < w; i++) {
    const a = ov((i + 0.5) / w);
    for (let j = 0; j < h; j++) { const k = (j * w + i) * 3; for (let n = 0; n < 3; n++) px[k + n] += (o.overlayRgb[n] - px[k + n]) * a; }
  }

  // PNG: RGB 8-bit, one filter byte per row
  const raw = Buffer.alloc((w * 3 + 1) * h);
  for (let j = 0; j < h; j++) for (let i = 0; i < w * 3; i++) raw[j * (w * 3 + 1) + 1 + i] = Math.round(px[j * w * 3 + i]);
  const crcT = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
  const crc = (b: Buffer) => { let c = 0xffffffff; for (const x of b) c = crcT[(c ^ x) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
  const chunk = (type: string, data: Buffer) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type), data]), c = Buffer.alloc(4); c.writeUInt32BE(crc(td));
    return Buffer.concat([len, td, c]);
  };
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 2;
  const png = Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(raw, { level: 9 })), chunk("IEND", Buffer.alloc(0))]);
  return `data:image/png;base64,${png.toString("base64")}`;
}
