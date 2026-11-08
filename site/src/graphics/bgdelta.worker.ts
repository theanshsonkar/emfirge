import { paintBackdrop, type MaskStops } from "./bgdeltaPaint";

// Renders the BgDelta backdrop off the main thread: OffscreenCanvas -> PNG blob, posted back to BgDelta.tsx.
export type BgJob = { id: number; w: number; h: number; dpr: number; stops: MaskStops | null };
export type BgResult = { id: number; blob?: Blob; error?: string };

const scope = self as unknown as { onmessage: ((e: MessageEvent<BgJob>) => void) | null; postMessage(m: BgResult): void };
scope.onmessage = async ({ data: { id, w, h, dpr, stops } }) => {
  try {
    const cv = new OffscreenCanvas(Math.round(w * dpr), Math.round(h * dpr));
    const ctx = cv.getContext("2d");
    if (!ctx) throw new Error("no 2d context");
    paintBackdrop(ctx, w, h, dpr, stops);
    scope.postMessage({ id, blob: await cv.convertToBlob({ type: "image/png" }) });
  } catch (e) {
    scope.postMessage({ id, error: String(e) });
  }
};
