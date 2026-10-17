// Public Supabase configuration. Filled in when Ansh provides the project's public values.
export const DEFAULT_SUPABASE_URL = "";
export const DEFAULT_SUPABASE_ANON_KEY = "";

export function supabaseUrl(): string {
  return (process.env.EMFIRGE_SUPABASE_URL || DEFAULT_SUPABASE_URL).replace(/\/+$/, "");
}

export function supabaseAnonKey(): string {
  return process.env.EMFIRGE_SUPABASE_ANON_KEY || DEFAULT_SUPABASE_ANON_KEY;
}

export function assertPublicKey(k: string): void {
  if (k.startsWith("sb_secret_")) throw new Error("Sign-in is misconfigured");
  try {
    const parts = k.split(".");
    if (parts.length === 3) {
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString()) as { role?: string };
      if (payload.role === "service_role") throw new Error("Sign-in is misconfigured");
    }
  } catch (e) {
    if (e instanceof Error && e.message === "Sign-in is misconfigured") throw e;
  }
}

export function assertConfigured(): void {
  const key = supabaseAnonKey();
  assertPublicKey(key);
  if (!supabaseUrl() || !key) {
    throw new Error("Browser sign-in isn't set up in this build yet. Set EMFIRGE_API_KEY instead.");
  }
}
