// Output: JSON by default (one document on stdout), a short readable form with --human.
// The input is already redacted by the handlers; nothing here adds raw data.

const MAX_DEPTH = 4;
const MAX_LIST = 8;

function scalar(v: unknown): string {
  if (v === null || v === undefined) return "none";
  if (typeof v === "string") return v.length > 120 ? `${v.slice(0, 117)}...` : v;
  return String(v);
}

function render(value: unknown, indent: string, depth: number, lines: string[]): void {
  if (Array.isArray(value)) {
    for (const item of value.slice(0, MAX_LIST)) {
      if (item !== null && typeof item === "object") {
        lines.push(`${indent}-`);
        render(item, indent + "  ", depth + 1, lines);
      } else lines.push(`${indent}- ${scalar(item)}`);
    }
    if (value.length > MAX_LIST) lines.push(`${indent}... ${value.length - MAX_LIST} more`);
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (v !== null && typeof v === "object") {
        if (depth >= MAX_DEPTH) { lines.push(`${indent}${k}: ...`); continue; }
        if (Array.isArray(v) && v.length === 0) { lines.push(`${indent}${k}: none`); continue; }
        lines.push(`${indent}${k}:`);
        render(v, indent + "  ", depth + 1, lines);
      } else lines.push(`${indent}${k}: ${scalar(v)}`);
    }
    return;
  }
  lines.push(`${indent}${scalar(value)}`);
}

type ChangedSetting = { resource_id?: unknown; resource_type?: unknown; field?: unknown; judged?: unknown };
type Answer = { damage?: string; facts?: unknown[]; checked?: unknown[]; unknown?: unknown[] };

function humanCheck(v: Record<string, unknown>): string | null {
  if (!Array.isArray(v.answers)) return null;
  const changeGroups = Array.isArray(v.changes) ? (v.changes as Array<{ resource_ids?: unknown[] }>) : [];
  const changeCount = changeGroups.reduce((n, g) => n + (Array.isArray(g.resource_ids) ? g.resource_ids.length : 0), 0);
  const lines = [`Branch check: ${scalar(v.branch_id)} (${changeCount} change(s))`];
  for (const a of v.answers as Answer[]) {
    const facts = a.facts?.length ?? 0;
    const unknown = a.unknown?.length ?? 0;
    lines.push(`- ${scalar(a.damage)}: ${facts} fact(s), ${unknown} unknown`);
    for (const f of (a.facts ?? []).slice(0, 3)) lines.push(`    fact: ${scalar(JSON.stringify(f))}`);
    for (const u of (a.unknown ?? []).slice(0, 3)) lines.push(`    unknown (not checked, not safe): ${scalar(JSON.stringify(u))}`);
  }
  const changed = Array.isArray(v.changed_settings) ? (v.changed_settings as ChangedSetting[]) : [];
  const unjudged = changed.filter((c) => c.judged !== true);
  if (changed.length) lines.push(`changed settings: ${changed.length} (${changed.length - unjudged.length} judged by a check, ${unjudged.length} not judged)`);
  if (unjudged.length) {
    lines.push("Changed, not judged:");
    for (const c of unjudged.slice(0, MAX_LIST)) lines.push(`    ${scalar(c.resource_type)} ${scalar(c.resource_id)}: ${scalar(c.field)}`);
    if (unjudged.length > MAX_LIST) lines.push(`    ... ${unjudged.length - MAX_LIST} more in the JSON form`);
  }
  if (v.baseline) lines.push("baseline: included in the JSON form");
  return lines.join("\n") + "\n";
}

export function formatOk(value: unknown, human: boolean): string {
  if (!human) return JSON.stringify(value, null, 2) + "\n";
  if (typeof value === "string") return value + "\n";
  if (value !== null && typeof value === "object") {
    const special = humanCheck(value as Record<string, unknown>);
    if (special) return special;
  }
  const lines: string[] = [];
  render(value, "", 0, lines);
  return lines.join("\n") + "\n";
}

export interface ErrorInfo { code: string; message: string; exit: number }

export function formatError(info: ErrorInfo, human: boolean): string {
  if (human) return `Error: ${info.message}\n`;
  return JSON.stringify({ error: info }) + "\n";
}
