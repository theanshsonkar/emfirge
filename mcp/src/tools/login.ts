import { z } from "zod";
import { assertConfigured, supabaseAnonKey, supabaseUrl } from "../auth/config.js";
import * as credentials from "../auth/credentials.js";
import { clearSession, getAccessToken } from "../auth/session.js";
import { startLogin } from "../auth/login.js";

export const loginSchema = {} as const;
export const loginZodObject = z.object(loginSchema);

export async function loginHandler(_args: Record<string, never>) {
  if (process.env.EMFIRGE_API_KEY) {
    return {
      content: [{
        type: "text" as const,
        text: "EMFIRGE_API_KEY is set, so Emfirge uses that key. Unset it to use browser sign-in.",
      }],
    };
  }
  if (await getAccessToken()) {
    return { content: [{ type: "text" as const, text: "You're already signed in." }] };
  }
  const { url } = await startLogin();
  return {
    content: [{
      type: "text" as const,
      text: `Opened your browser to sign in (GitHub or Google). If it didn't open, go to ${url}. Then run your request again.`,
    }],
  };
}

export const logoutSchema = {} as const;
export const logoutZodObject = z.object(logoutSchema);

export async function logoutHandler(_args: Record<string, never>) {
  if (process.env.EMFIRGE_API_KEY) {
    credentials.remove();
    clearSession();
    return { content: [{ type: "text" as const, text: "Signed out." }] };
  }
  const access = await getAccessToken();
  if (access) {
    try {
      assertConfigured();
      await fetch(`${supabaseUrl()}/auth/v1/logout?scope=local`, {
        method: "POST",
        headers: {
          apikey: supabaseAnonKey(),
          Authorization: `Bearer ${access}`,
        },
      });
    } catch {
      // Logout remains local even when the provider is unreachable.
    }
  }
  credentials.remove();
  clearSession();
  return { content: [{ type: "text" as const, text: "Signed out." }] };
}
