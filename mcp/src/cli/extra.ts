// AWS CLI shorthand detection for `emfirge try --aws-cli`.

/** Split a command line on whitespace, honoring single and double quotes (no expansion). */
function shellWords(command: string): string[] {
  const words: string[] = [];
  let cur = "";
  let has = false;
  let quote: "'" | '"' | null = null;
  for (const ch of command) {
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
      has = true;
    } else if (/\s/.test(ch)) {
      if (has || cur) words.push(cur);
      cur = "";
      has = false;
    } else {
      cur += ch;
    }
  }
  if (has || cur) words.push(cur);
  return words;
}

/**
 * The first AWS CLI shorthand value in a command, or undefined. Shorthand is `Key=value,Key2=value2`, for example
 * `--target Arn=...,RoleArn=...` or `--flexible-time-window Mode=OFF`. The backend does not read it and will not guess
 * what it means, so the CLI names it before any request is sent.
 */
export function findShorthand(command: string): { option: string; value: string } | undefined {
  const words = shellWords(command);
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (!w.startsWith("--")) continue;
    const eq = w.indexOf("=");
    const option = eq > 0 ? w.slice(0, eq) : w;
    const value = eq > 0 ? w.slice(eq + 1) : words[i + 1];
    if (value !== undefined && /^[A-Z][A-Za-z0-9]*=/.test(value)) return { option, value };
  }
  return undefined;
}
