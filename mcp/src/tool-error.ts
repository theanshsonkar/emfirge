import { redactDeep } from "./tokenize.js";

export function formatToolError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return `Error: ${redactDeep(message)}`;
}
