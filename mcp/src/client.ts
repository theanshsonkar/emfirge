// HTTP client. Override base URL with EMFIRGE_BASE_URL.
// X-MCP header tells the backend to skip its AI summary (host LLM does that).

const BASE_URL = process.env.EMFIRGE_BASE_URL ?? "https://emfirge.cloud/api";

export interface ClientOptions {
  timeout?: number;
}

export async function backendCall<T = unknown>(
  method: "GET" | "POST",
  path: string,
  body?: Record<string, unknown>,
  opts: ClientOptions = {},
): Promise<T> {
  const url = `${BASE_URL}${path}`;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-MCP": "1",
    "X-Source": "mcp",
  };

  const controller = new AbortController();
  const timeoutMs = opts.timeout ?? 90_000;
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });

    if (!res.ok) {
      const text = await res.text();

      if (res.status === 429) {
        throw new Error(
          extractDetail(text) ??
            "Daily limit reached for this AWS account. Resets at midnight UTC.",
        );
      }
      if (res.status === 403) {
        throw new Error(
          "Access denied. Check the role's trust policy and ExternalId 'aws-risk-agent'. " +
            "If you don't have a role yet, call emfirge_setup_help.",
        );
      }
      if (res.status === 404) {
        throw new Error(
          `Not found at ${path}. If you passed an analysis_id, run emfirge_scan first.`,
        );
      }

      throw new Error(`Backend ${res.status} on ${path}: ${text.slice(0, 300)}`);
    }

    return (await res.json()) as T;
  } catch (e) {
    if (e instanceof Error && e.name === "AbortError") {
      throw new Error(`${path} timed out after ${timeoutMs / 1000}s`);
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

export function getBaseUrl(): string {
  return BASE_URL;
}

// FastAPI returns errors as {"detail": "..."}. Surfacing that verbatim keeps
// user-facing limits (e.g. "5/day, resets midnight UTC") accurate without the
// client hardcoding numbers that drift when the backend changes them.
function extractDetail(text: string): string | null {
  try {
    const j = JSON.parse(text) as { detail?: unknown };
    if (typeof j.detail === "string" && j.detail.trim()) return j.detail;
  } catch {
    /* not JSON */
  }
  return null;
}

// Streaming variant for endpoints that return SSE (currently just /simulate
// and /analyze/stream). Reads the event stream, returns the data payload of
// the final `complete` event. Throws on `error` events.
//
// Backend SSE format (per backend-api.md):
//   event: progress|preview|complete|error
//   data: {...json...}
//
// We don't surface progress/preview events to the host LLM — they'd just be
// noise. Only the final consolidated payload matters in non-streaming clients.
export async function backendCallSSE<T = unknown>(
  method: "GET" | "POST",
  path: string,
  body?: Record<string, unknown>,
  opts: ClientOptions = {},
): Promise<T> {
  const url = `${BASE_URL}${path}`;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "text/event-stream",
    "X-MCP": "1",
    "X-Source": "mcp",
  };

  const controller = new AbortController();
  const timeoutMs = opts.timeout ?? 90_000;
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });

    if (!res.ok) {
      const text = await res.text();
      if (res.status === 429) {
        throw new Error(
          extractDetail(text) ??
            "Daily limit reached for this AWS account. Resets at midnight UTC.",
        );
      }
      if (res.status === 404) {
        throw new Error(
          `Not found at ${path}. If you passed an analysis_id, run emfirge_scan first.`,
        );
      }
      throw new Error(`Backend ${res.status} on ${path}: ${text.slice(0, 300)}`);
    }

    if (!res.body) {
      throw new Error(`No response body from ${path}`);
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let lastComplete: T | null = null;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      // SSE frames are separated by a blank line (\n\n or \r\n\r\n)
      let frameEnd: number;
      while ((frameEnd = findFrameEnd(buffer)) !== -1) {
        const frame = buffer.slice(0, frameEnd);
        buffer = buffer.slice(frameEnd).replace(/^(?:\r?\n){2}/, "");

        let eventType = "message";
        const dataLines: string[] = [];
        for (const rawLine of frame.split(/\r?\n/)) {
          if (rawLine.startsWith("event:")) {
            eventType = rawLine.slice(6).trim();
          } else if (rawLine.startsWith("data:")) {
            // SSE allows multi-line data; strip leading space per spec
            dataLines.push(rawLine.slice(5).replace(/^\s/, ""));
          }
        }
        const dataStr = dataLines.join("\n");
        if (!dataStr) continue;

        if (eventType === "error") {
          let parsed: { message?: string } = {};
          try {
            parsed = JSON.parse(dataStr);
          } catch {
            /* ignore malformed error frame */
          }
          throw new Error(
            parsed.message ?? `${path} returned an error event`,
          );
        }

        if (eventType === "complete") {
          try {
            lastComplete = JSON.parse(dataStr) as T;
          } catch {
            // ignore malformed complete frame and keep reading
          }
        }
        // event: progress / preview — intentionally ignored
      }
    }

    if (lastComplete === null) {
      throw new Error(
        `${path} stream ended without a 'complete' event. The backend may have timed out.`,
      );
    }
    return lastComplete;
  } catch (e) {
    if (e instanceof Error && e.name === "AbortError") {
      throw new Error(`${path} timed out after ${timeoutMs / 1000}s`);
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

// Find the index immediately after the next blank-line frame separator
// (\n\n or \r\n\r\n). Returns -1 if no full frame is in the buffer yet.
function findFrameEnd(buf: string): number {
  const lf = buf.indexOf("\n\n");
  const crlf = buf.indexOf("\r\n\r\n");
  if (lf === -1 && crlf === -1) return -1;
  if (lf === -1) return crlf;
  if (crlf === -1) return lf;
  return Math.min(lf, crlf);
}
