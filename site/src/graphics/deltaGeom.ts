// Geometry of the generated river delta (design space 640x266): Catmull-Rom channels, the paths the "changes" travel,
// and colour helpers. Shared by the hero canvas (Delta.tsx) and the share image (app/opengraph-image.tsx).
export type P = [number, number];
export const DW = 640, DH = 266;

export function spline(pts: P[], step = 3): P[] {
  const out: P[] = [];
  const g = (i: number) => pts[Math.max(0, Math.min(pts.length - 1, i))];
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = g(i - 1), p1 = g(i), p2 = g(i + 1), p3 = g(i + 2);
    const len = Math.hypot(p2[0] - p1[0], p2[1] - p1[1]);
    const n = Math.max(2, Math.round(len / step));
    for (let k = 0; k < n; k++) {
      const t = k / n, t2 = t * t, t3 = t2 * t;
      out.push([
        0.5 * (2 * p1[0] + (-p0[0] + p2[0]) * t + (2 * p0[0] - 5 * p1[0] + 4 * p2[0] - p3[0]) * t2 + (-p0[0] + 3 * p1[0] - 3 * p2[0] + p3[0]) * t3),
        0.5 * (2 * p1[1] + (-p0[1] + p2[1]) * t + (2 * p0[1] - 5 * p1[1] + 4 * p2[1] - p3[1]) * t2 + (-p0[1] + 3 * p1[1] - 3 * p2[1] + p3[1]) * t3),
      ]);
    }
  }
  out.push(pts[pts.length - 1]);
  return out;
}
const join = (...a: P[][]) => a.flat();

const TRUNK: P[] = [[-20, 140], [80, 130], [150, 144], [215, 136]];
const A: P[] = [[215, 136], [270, 112], [330, 86], [400, 72], [470, 66]];
const A1: P[] = [[470, 66], [560, 52], [660, 38]];
const A2: P[] = [[470, 66], [540, 88], [660, 98]];
const B: P[] = [[215, 136], [265, 160], [330, 180], [400, 196], [470, 200]];
const B1: P[] = [[470, 200], [560, 214], [660, 228]];
const B2: P[] = [[470, 200], [540, 176], [660, 170]];
const CREEKS: { pts: P[]; w: number }[] = [
  { pts: [[330, 86], [368, 44], [410, 6], [430, -10]], w: 1.4 },
  { pts: [[330, 180], [378, 224], [418, 262], [430, 280]], w: 1.4 },
  { pts: [[150, 144], [172, 190], [188, 240], [196, 280]], w: 1.2 },
  { pts: [[80, 130], [110, 90], [130, 40], [128, -10]], w: 1.2 },
  { pts: [[560, 52], [590, 70], [640, 80]], w: 1.1 },
  { pts: [[560, 214], [590, 196], [640, 192]], w: 1.1 },
];
export const SEGS: { pts: P[]; w: number }[] = [
  { pts: spline(TRUNK), w: 4.2 },
  { pts: spline(A), w: 3.2 }, { pts: spline(B), w: 3.2 },
  { pts: spline(A1), w: 2.2 }, { pts: spline(A2), w: 2.2 },
  { pts: spline(B1), w: 2.2 }, { pts: spline(B2), w: 2.2 },
  ...CREEKS.map((c) => ({ pts: spline(c.pts), w: c.w })),
];
export const PATHS = {
  A1: spline(join(TRUNK, A.slice(1), A1.slice(1)), 2),
  A2: spline(join(TRUNK, A.slice(1), A2.slice(1)), 2),
  B1: spline(join(TRUNK, B.slice(1), B1.slice(1)), 2),
  B2: spline(join(TRUNK, B.slice(1), B2.slice(1)), 2),
};
export type PathName = keyof typeof PATHS;
const cum = (pts: P[]) => { const c = [0]; for (let i = 1; i < pts.length; i++) c.push(c[i - 1] + Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1])); return c; };
const LEN: Record<PathName, number[]> = { A1: cum(PATHS.A1), A2: cum(PATHS.A2), B1: cum(PATHS.B1), B2: cum(PATHS.B2) };
export function at(name: PathName, f: number): P {
  const pts = PATHS[name], c = LEN[name], d = f * c[c.length - 1];
  let i = 1; while (i < c.length - 1 && c[i] < d) i++;
  const k = (d - c[i - 1]) / Math.max(1e-6, c[i] - c[i - 1]);
  return [pts[i - 1][0] + (pts[i][0] - pts[i - 1][0]) * k, pts[i - 1][1] + (pts[i][1] - pts[i - 1][1]) * k];
}

export const hex = (h: string): [number, number, number] => [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)];
export const mix = (a: [number, number, number], b: [number, number, number], t: number) => `rgb(${Math.round(a[0] + (b[0] - a[0]) * t)},${Math.round(a[1] + (b[1] - a[1]) * t)},${Math.round(a[2] + (b[2] - a[2]) * t)})`;

