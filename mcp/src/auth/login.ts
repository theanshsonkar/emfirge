import * as http from "node:http";
import { randomBytes, createHash, timingSafeEqual } from "node:crypto";
import { execFile } from "node:child_process";
import { assertConfigured, supabaseAnonKey, supabaseUrl } from "./config.js";
import * as credentials from "./credentials.js";
import { setSession } from "./session.js";

type Pending = { url: string; pending: Promise<boolean> };
let active: Pending | null = null;
const headers = { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'" };
function page(res: http.ServerResponse, status: number, text: string, location?: string) { res.writeHead(status, { ...headers, ...(location ? { Location: location } : {}) }); res.end(`<html><body>${text}</body></html>`); }
export async function startLogin(opts: { timeoutMs?: number } = {}): Promise<Pending> {
  if (active) return active;
  assertConfigured();
  const state = randomBytes(32).toString("base64url"), verifier = randomBytes(32).toString("base64url"), challenge = createHash("sha256").update(verifier).digest("base64url");
  const server = http.createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port, base = `http://127.0.0.1:${port}`, url = base + "/";
  let done = false; let resolvePending!: (value: boolean) => void;
  const pending = new Promise<boolean>((resolve) => { resolvePending = resolve; });
  const finish = (ok: boolean) => { if (done) return; done = true; resolvePending(ok); clearTimeout(timer); server.close(); active = null; };
  const timer = setTimeout(() => finish(false), opts.timeoutMs ?? 300_000);
  server.on("request", async (req, res) => {
    if (req.headers.host !== `127.0.0.1:${port}`) return page(res, 400, "Bad request.");
    if (req.method !== "GET") return page(res, 404, "Not found.");
    const parsed = new URL(req.url || "/", base), pathname = parsed.pathname;
    if (pathname === "/") return page(res, 200, '<a href="/start/github">Continue with GitHub</a><br><a href="/start/google">Continue with Google</a>');
    if (pathname === "/start/github" || pathname === "/start/google") { const provider = pathname.split("/").pop(); const redirect = `${base}/callback/${state}`; return page(res, 302, "Redirecting.", `${supabaseUrl()}/auth/v1/authorize?provider=${provider}&redirect_to=${encodeURIComponent(redirect)}&code_challenge=${challenge}&code_challenge_method=s256`); }
    if (pathname.startsWith("/callback/")) {
      if (done) return page(res, 410, "This sign-in has already finished.");
      const supplied = pathname.slice("/callback/".length), a = Buffer.from(supplied), b = Buffer.from(state);
      if (a.length !== b.length || !timingSafeEqual(a, b)) return page(res, 400, "This sign-in link doesn't match. Start again from your AI.");
      if (parsed.searchParams.has("error")) { page(res, 200, "Sign-in didn't finish. Start again from your AI."); return finish(false); }
      const code = parsed.searchParams.get("code"); if (!code) { page(res, 400, "Sign-in didn't finish. Start again from your AI."); return; }
      try {
        const response = await fetch(`${supabaseUrl()}/auth/v1/token?grant_type=pkce`, { method: "POST", headers: { apikey: supabaseAnonKey(), "Content-Type": "application/json" }, body: JSON.stringify({ auth_code: code, code_verifier: verifier }) });
        if (response.status !== 200) { page(res, 200, "Sign-in didn't finish. Start again from your AI."); return finish(false); }
        const data = await response.json() as { access_token?: string; expires_in?: number; refresh_token?: string };
        if (!data.access_token || !data.refresh_token) { page(res, 200, "Sign-in didn't finish. Start again from your AI."); return finish(false); }
        credentials.save(data.refresh_token); setSession(data.access_token, data.expires_in ?? 3600, data.refresh_token); page(res, 200, "You're signed in. Go back to your AI."); finish(true);
      } catch { page(res, 200, "Sign-in didn't finish. Start again from your AI."); finish(false); }
      return;
    }
    page(res, 404, "Not found.");
  });
  active = { url, pending };
  if (process.env.EMFIRGE_NO_BROWSER !== "1") { const platform = process.platform; const command = platform === "darwin" ? "open" : platform === "win32" ? "cmd" : "xdg-open"; const args = platform === "darwin" ? [url] : platform === "win32" ? ["/c", "start", "", url] : [url]; execFile(command, args, () => {}); }
  return active;
}
