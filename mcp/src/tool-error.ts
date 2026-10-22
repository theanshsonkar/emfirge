import { ZodError } from "zod";
import { redactDeep } from "./tokenize.js";

export function formatToolError(error: unknown): string {
  if (error instanceof ZodError) {
    const shown = error.issues.slice(0, 5).map((issue) => {
      const path = issue.path.length > 0 ? issue.path.join(".") : "input";
      return `${path}: ${issue.message}`;
    });
    const remaining = error.issues.length - shown.length;
    const suffix = remaining > 0 ? ` (+${remaining} more)` : "";
    return String(redactDeep(
      `Error: Invalid input: ${shown.join("; ")}${suffix} See the tool description for the expected shape.`,
    ));
  }
  const message = error instanceof Error ? error.message : String(error);
  return `Error: ${redactDeep(message)}`;
}
