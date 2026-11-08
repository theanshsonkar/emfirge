// Shared dot-matrix generators: isometric quads rasterised onto a fine dot grid (used by Iso, the branch figure and
// the coverage icons). No React in here, so any canvas component can use it.
export type V3 = [number, number, number];
export type Quad = { o: V3; a: V3; b: V3; shade: number; grp: number; pat?: (u: number, v: number, t: number) => number };

export const proj = (p: V3): [number, number] => [(p[0] - p[1]) * 0.866, (p[0] + p[1]) * 0.5 - p[2]];
export const add = (p: V3, q: V3, k = 1): V3 => [p[0] + q[0] * k, p[1] + q[1] * k, p[2] + q[2] * k];
export const edge = (u: number, v: number, e: number) => u < e || v < e || u > 1 - e || v > 1 - e;

export function box(x: number, y: number, z: number, sx: number, sy: number, sz: number, grp: number, pats: { top?: Quad["pat"]; left?: Quad["pat"]; right?: Quad["pat"] } = {}): Quad[] {
  return [
    { o: [x, y, z + sz], a: [sx, 0, 0], b: [0, sy, 0], shade: 0.55, grp, pat: pats.top },
    { o: [x, y + sy, z], a: [sx, 0, 0], b: [0, 0, sz], shade: 1, grp, pat: pats.left },
    { o: [x + sx, y, z], a: [0, sy, 0], b: [0, 0, sz], shade: 0.78, grp, pat: pats.right },
  ];
}

export type Dot = { x: number; y: number; q: number; u: number; v: number };

/** Screen-space affine fit: scale s and offset so the quads' bounds sit centred in w x h with `fill` of the box. */
export function fit(quads: Quad[], w: number, h: number, fill = 0.9) {
  const pts: [number, number][] = [];
  quads.forEach((q) => [q.o, add(q.o, q.a), add(q.o, q.b), add(add(q.o, q.a), q.b)].forEach((p) => pts.push(proj(p))));
  const minX = Math.min(...pts.map((p) => p[0])), maxX = Math.max(...pts.map((p) => p[0]));
  const minY = Math.min(...pts.map((p) => p[1])), maxY = Math.max(...pts.map((p) => p[1]));
  const s = Math.min((w * fill) / (maxX - minX), (h * fill) / (maxY - minY));
  return { s, ox: (w - (maxX - minX) * s) / 2 - minX * s, oy: (h - (maxY - minY) * s) / 2 - minY * s };
}

/**
 * Rasterise quads onto a dot grid of `pitch` px. Later quads draw on top of earlier ones.
 * Only the grid cells inside each quad's bounding box are tested, so many small scenes stay cheap.
 */
export function rasterQuads(quads: Quad[], s: number, ox: number, oy: number, pitch: number, w: number, h: number): Dot[] {
  const sp = (p: V3): [number, number] => { const q = proj(p); return [q[0] * s + ox, q[1] * s + oy]; };
  const taken = new Map<number, Dot>();
  const cols = Math.floor(w / pitch);
  quads.forEach((q, qi) => {
    const P0 = sp(q.o), A = sp(add(q.o, q.a)), B = sp(add(q.o, q.b)), C = sp(add(add(q.o, q.a), q.b));
    const ax = A[0] - P0[0], ay = A[1] - P0[1], bx = B[0] - P0[0], by = B[1] - P0[1];
    const det = ax * by - ay * bx;
    if (Math.abs(det) < 1e-6) return;
    const xs = [P0[0], A[0], B[0], C[0]], ys = [P0[1], A[1], B[1], C[1]];
    const i0 = Math.max(0, Math.floor(Math.min(...xs) / pitch)), i1 = Math.min(cols - 1, Math.ceil(Math.max(...xs) / pitch));
    const j0 = Math.max(0, Math.floor(Math.min(...ys) / pitch)), j1 = Math.min(Math.floor(h / pitch) - 1, Math.ceil(Math.max(...ys) / pitch));
    for (let j = j0; j <= j1; j++) for (let i = i0; i <= i1; i++) {
      const x = (i + 0.5) * pitch, y = (j + 0.5) * pitch;
      const dx = x - P0[0], dy = y - P0[1];
      const u = (dx * by - dy * bx) / det, v = (ax * dy - ay * dx) / det;
      if (u >= -0.001 && u <= 1.001 && v >= -0.001 && v <= 1.001) taken.set(j * cols + i, { x, y, q: qi, u: Math.min(1, Math.max(0, u)), v: Math.min(1, Math.max(0, v)) });
    }
  });
  return [...taken.values()];
}

/** The v6 green ramp: top faces lightest, left faces darkest. */
export const faceColor = (shade: number, a: number) =>
  shade > 0.9 ? `rgba(10,122,75,${a})` : shade > 0.7 ? `rgba(32,150,100,${a})` : `rgba(90,190,148,${a})`;
