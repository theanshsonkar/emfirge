"use client";
import { useCallback, useRef } from "react";
import { box, edge, faceColor, fit, rasterQuads, type Dot, type Quad } from "./dots";
import { useCanvas, type DrawFn } from "./useCanvas";

// Coverage figure: one tiny isometric dot icon per resource type, with add / modify / delete pips. One canvas, drawn once, lit in turn when in view.
const bands = (n: number) => (u: number, v: number) => (edge(u, v, 0.06) ? 1 : Math.floor(v * n) % 2 === 0 ? 0.9 : 0.3);
const cols = (n: number) => (u: number, v: number) => (edge(u, v, 0.06) ? 1 : Math.floor(u * n) % 2 === 0 ? 0.9 : 0.3);
const grid = (n: number) => (u: number, v: number) => (edge(u, v, 0.06) ? 1 : Math.floor(u * n) % 2 === 0 || Math.floor(v * n) % 2 === 0 ? 0.75 : 0.1);
const solid = (u: number, v: number): number => (edge(u, v, 0.08) ? 1 : 0.55);
const dashed = (u: number, v: number): number => (edge(u, v, 0.1) ? ((Math.floor(u * 8) + Math.floor(v * 8)) % 2 === 0 ? 1 : 0.4) : 0.14);
const key = (u: number, v: number) => { const d = Math.hypot(u - 0.35, v - 0.45); return d < 0.2 && d > 0.1 ? 1 : v > 0.42 && v < 0.5 && u > 0.5 && u < 0.85 ? 1 : edge(u, v, 0.05) ? 0.6 : 0.15; };
const disk = (z: number, g: number, p: (u: number, v: number) => number = solid) => box(0, 0, z, 6, 6, 0.9, g, { top: p, left: p, right: p });

type Item = { name: string; ops: string; scene: Quad[] };
const ITEMS: Item[] = [
  { name: "ec2_instance", ops: "amd", scene: box(0, 0, 0, 6, 6, 5, 0, { top: grid(4), left: bands(6), right: cols(6) }) },
  { name: "security_group", ops: "amd", scene: [...box(0, 0, 0, 7, 7, 0.8, 0, { top: (u, v) => (edge(u, v, 0.1) && !(v > 0.8 && u > 0.35 && u < 0.65) ? 1 : 0.08) }), ...box(0, 0, 0.8, 7, 0.8, 3.2, 1, { left: bands(8) })] },
  { name: "rds_instance", ops: "amd", scene: [disk(0, 0, bands(3)), disk(1.3, 1, bands(3)), disk(2.6, 2, bands(3))].flat() },
  { name: "s3_bucket", ops: "amd", scene: box(0, 0, 0, 8, 6, 3.4, 0, { top: (u, v) => (edge(u, v, 0.1) ? 1 : 0.18), left: bands(8), right: bands(8) }) },
  { name: "lambda_function", ops: "amd", scene: [...box(0, 0, 0, 3, 3, 3, 0, { top: solid, left: solid, right: solid }), ...box(3, 3, 2, 3, 3, 3, 1, { top: solid, left: solid, right: solid })] },
  { name: "network_acl", ops: "amd", scene: box(0, 0, 0, 8, 8, 0.9, 0, { top: grid(8), left: solid, right: solid }) },
  { name: "iam_role", ops: "amd", scene: box(0, 0, 0, 6, 6, 4.5, 0, { top: solid, left: key, right: bands(5) }) },
  { name: "iam_role_policy", ops: "m", scene: [0, 1.5, 3].flatMap((z, i) => box(0, 0, z, 7, 7, 0.5, i, { top: bands(7), left: solid, right: solid })) },
  { name: "iam_user", ops: "a", scene: [...box(0, 0, 0, 7, 4, 2.5, 0, { top: solid, left: solid, right: solid }), ...box(2, 0.5, 2.5, 3, 3, 3, 1, { top: solid, left: solid, right: solid })] },
  { name: "nat_gateway", ops: "a", scene: box(0, 0, 0, 6, 6, 3.5, 0, { top: (u, v) => (Math.abs(u - 0.5) < 0.09 || (v < 0.32 && Math.abs(u - 0.5) < 0.4 - v) ? 1 : edge(u, v, 0.08) ? 1 : 0.2), left: solid, right: bands(5) }) },
  { name: "route_table", ops: "am", scene: box(0, 0, 0, 8, 8, 0.9, 0, { top: (u, v) => (edge(u, v, 0.05) || Math.abs(v - 0.5) < 0.07 || (u > 0.5 && Math.abs(v - 0.2) < 0.06) || (u > 0.5 && Math.abs(v - 0.8) < 0.06) ? 1 : 0.1), left: solid, right: solid }) },
  { name: "rds_snapshot", ops: "ad", scene: [disk(0, 0, dashed), disk(1.4, 1, dashed)].flat() },
  { name: "ebs_volume", ops: "ad", scene: box(0, 0, 0, 5, 5, 4.6, 0, { top: solid, left: bands(7), right: bands(7) }) },
  { name: "ebs_snapshot", ops: "d", scene: box(0, 0, 0, 5, 5, 3.4, 0, { top: dashed, left: dashed, right: dashed }) },
];

export function CoverageFig() {
  const cache = useRef<{ key: string; dots: Dot[][]; cw: number; ch: number; n: number } | null>(null);
  const draw = useCallback<DrawFn>((ctx, w, h, t, still) => {
    const n = w >= 560 ? 7 : 5, rows = Math.ceil(ITEMS.length / n);
    const cw = w / n, ch = h / rows, k = `${w}x${h}`;
    const art = Math.min(cw * 0.78, ch * 0.5);
    if (!cache.current || cache.current.key !== k) {
      const pitch = cw < 80 ? 2.6 : 3.2;
      cache.current = { key: k, cw, ch, n, dots: ITEMS.map((it) => { const f = fit(it.scene, art, art * 0.82, 0.96); return rasterQuads(it.scene, f.s, f.ox, f.oy, pitch, art, art * 0.82); }) };
    }
    ctx.clearRect(0, 0, w, h);
    const mono = getComputedStyle(document.documentElement).getPropertyValue("--font-geist-mono") || "monospace";
    ctx.font = `500 ${cw < 80 ? 7 : 8}px ${mono}`; ctx.textAlign = "center"; ctx.textBaseline = "alphabetic";
    ITEMS.forEach((it, i) => {
      const cx = (i % n) * cw + cw / 2, top = Math.floor(i / n) * ch + 12;
      const on = still ? 1 : Math.min(1, Math.max(0, (t - i * 0.11) / 0.5));
      const ox = cx - art / 2, oy = top;
      for (const d of cache.current!.dots[i]) {
        const q = it.scene[d.q];
        const kk = q.pat ? q.pat(d.u, d.v, t) : 0.6;
        if (kk <= 0.04) continue;
        const a = (0.55 + 0.45 * q.shade) * Math.max(kk, 0.25) * on;
        const size = 1.3 + 1.1 * Math.min(1, a);
        ctx.fillStyle = faceColor(q.shade, a);
        ctx.fillRect(ox + d.x - size / 2, oy + d.y - size / 2, size, size);
      }
      const ly = top + art * 0.82 + 14;
      ctx.fillStyle = `rgba(11,16,21,${0.6 * on})`;
      ctx.fillText(it.name, cx, ly);
      // pips: add (green), modify (outlined), delete (red)
      const px = cx - 11;
      [["a", "#0A7A4B"], ["m", "#0B1015"], ["d", "#C4574A"]].forEach(([op, col], j) => {
        const has = it.ops.includes(op), x = px + j * 11, y = ly + 6;
        ctx.globalAlpha = (has ? 1 : 0.35) * on;
        if (!has) { ctx.fillStyle = "rgba(11,16,21,.25)"; ctx.fillRect(x + 2, y + 2, 2, 2); }
        else if (op === "m") { ctx.strokeStyle = col; ctx.lineWidth = 1; ctx.strokeRect(x + 0.5, y + 0.5, 5, 5); }
        else { ctx.fillStyle = col; ctx.fillRect(x, y, 6, 6); }
        ctx.globalAlpha = 1;
      });
    });
  }, []);
  const ref = useCanvas(draw, { fps: 20 });
  return <canvas ref={ref} className="cv covfig" role="img" aria-label="Fourteen resource types, each marked with the operations a branch supports" />;
}
export default CoverageFig;
