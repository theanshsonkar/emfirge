import { z } from "zod";
import { getBaseUrl } from "../client.js";
import { assertConfigured } from "../auth/config.js";
import { getAccessToken } from "../auth/session.js";
import { redactDeep } from "../tokenize.js";

export const linkProjectSchema = {} as const;
export const linkProjectZodObject = z.object(linkProjectSchema);

export async function linkProjectHandler(_args: Record<string, never>) {
  const key = process.env.EMFIRGE_API_KEY;
  if (!key) {
    return { content: [{ type: "text" as const, text: "Set EMFIRGE_API_KEY in your MCP settings, then run this tool again." }] };
  }
  assertConfigured();
  const token = await getAccessToken();
  if (!token) {
    return { content: [{ type: "text" as const, text: "Sign in first with emfirge_login, then run this tool again." }] };
  }

  try {
    const response = await fetch(`${getBaseUrl()}/auth/link-project`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "X-Emfirge-Link-Key": key,
        "X-MCP": "1",
        "X-Source": "mcp",
      },
    });
    if (!response.ok) {
      const body = await response.text();
      let detail = body;
      try {
        const parsed = JSON.parse(body) as { detail?: unknown };
        if (typeof parsed.detail === "string") detail = parsed.detail;
      } catch { /* preserve generic response text */ }
      throw new Error(detail);
    }
    return {
      content: [{
        type: "text" as const,
        text: "Linked. Remove EMFIRGE_API_KEY from your MCP settings and restart; you'll stay signed in.",
      }],
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Link failed";
    throw new Error(String(redactDeep(message)));
  }
}
