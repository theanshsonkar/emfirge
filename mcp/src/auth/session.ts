import { supabaseAnonKey, supabaseUrl, assertConfigured } from "./config.js";
import * as credentials from "./credentials.js";

let memory: { accessToken: string; expiresAt: number } | null = null;
let refreshFlight: Promise<string | null> | null = null;

export function setSession(accessToken: string, expiresIn: number, refreshToken: string): void {
  memory = {
    accessToken,
    expiresAt: Date.now() + expiresIn * 1000,
  };
  credentials.save(refreshToken);
}

export function clearSession(): void {
  memory = null;
}

export function forceExpire(): void {
  if (memory) memory.expiresAt = 0;
}

export function _resetForTests(): void {
  memory = null;
  refreshFlight = null;
}

export async function getAccessToken(): Promise<string | null> {
  if (memory && memory.expiresAt - Date.now() > 60_000) return memory.accessToken;
  if (!refreshFlight) refreshFlight = refresh().finally(() => {
    refreshFlight = null;
  });
  return refreshFlight;
}

async function refresh(): Promise<string | null> {
  const stored = credentials.load();
  if (!stored) return null;
  try {
    assertConfigured();
    const response = await fetch(`${supabaseUrl()}/auth/v1/token?grant_type=refresh_token`, {
      method: "POST",
      headers: {
        apikey: supabaseAnonKey(),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ refresh_token: stored.refreshToken }),
    });
    if (response.status === 200) {
      const data = await response.json() as {
        access_token?: string;
        expires_in?: number;
        refresh_token?: string;
      };
      if (!data.access_token || !data.refresh_token) {
        throw new Error("Could not reach the sign-in service. Try again.");
      }
      setSession(data.access_token, data.expires_in ?? 3600, data.refresh_token);
      return data.access_token;
    }
    if (response.status === 400 || response.status === 401) {
      credentials.remove();
      clearSession();
      return null;
    }
    throw new Error("Could not reach the sign-in service. Try again.");
  } catch (e) {
    if (e instanceof Error && e.message === "Could not reach the sign-in service. Try again.") throw e;
    throw new Error("Could not reach the sign-in service. Try again.");
  }
}
