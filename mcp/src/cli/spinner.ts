// A small "working" spinner for a person at a terminal. It writes only to stderr, and only when stderr
// is a terminal, so an agent reading stdout as JSON never sees it. Off in CI, on TERM=dumb, or with
// EMFIRGE_NO_SPINNER=1.

const FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const CLEAR = "\r\x1b[K";

interface SpinStream {
  isTTY?: boolean;
  write: (s: string) => unknown;
}

export function spinnerEnabled(stream: { isTTY?: boolean }, env: Record<string, string | undefined>): boolean {
  if (!stream.isTTY) return false;
  if (env.CI || env.EMFIRGE_NO_SPINNER || env.TERM === "dumb") return false;
  return true;
}

export function startSpinner(
  label: string,
  opts: { stream?: SpinStream; env?: Record<string, string | undefined>; intervalMs?: number } = {},
): () => void {
  const stream = opts.stream ?? process.stderr;
  const env = opts.env ?? process.env;
  if (!spinnerEnabled(stream, env)) return () => {};
  let i = 0;
  const draw = () => { stream.write(`${CLEAR}${FRAMES[i++ % FRAMES.length]} ${label}…`); };
  draw();
  const timer = setInterval(draw, opts.intervalMs ?? 80);
  timer.unref?.();
  let stopped = false;
  return () => {
    if (stopped) return;
    stopped = true;
    clearInterval(timer);
    stream.write(CLEAR);
  };
}
