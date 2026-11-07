// Private local state under ~/.emfirge: directory 0700, files 0600, written via temp file + rename
// (same pattern as auth/credentials.ts).
import * as fs from "node:fs";
import * as path from "node:path";

export function ensurePrivateDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dir, 0o700);
}

export function writePrivateFile(dir: string, file: string, content: string): void {
  ensurePrivateDir(dir);
  const tmp = path.join(dir, `.${path.basename(file)}.${process.pid}.${Date.now()}.tmp`);
  try {
    fs.writeFileSync(tmp, content, { mode: 0o600, flag: "wx" });
    fs.chmodSync(tmp, 0o600);
    fs.renameSync(tmp, file);
  } finally {
    try {
      fs.unlinkSync(tmp);
    } catch {
      // The temporary file was already renamed or did not exist.
    }
  }
}

/** Tighten an existing file or directory that is readable by group/others. Missing paths are ignored. */
export function tightenIfOpen(target: string, privateMode: number): void {
  try {
    if ((fs.statSync(target).mode & 0o077) !== 0) fs.chmodSync(target, privateMode);
  } catch {
    // Missing or not ours to change; nothing to tighten.
  }
}
