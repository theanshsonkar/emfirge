import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { supabaseUrl } from "./config.js";

function locations(): { dir: string; file: string } {
  const dir = path.join(process.env.HOME ?? os.homedir(), ".emfirge");
  return { dir, file: path.join(dir, "credentials.json") };
}

export function save(refreshToken: string): void {
  const { dir, file } = locations();
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dir, 0o700);
  const tmp = path.join(dir, `.credentials.${process.pid}.${Date.now()}.tmp`);
  const json = JSON.stringify({
    version: 1,
    supabase_url: supabaseUrl(),
    refresh_token: refreshToken,
  });
  try {
    fs.writeFileSync(tmp, json, { mode: 0o600, flag: "wx" });
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

export function load(): { refreshToken: string } | null {
  const { file } = locations();
  try {
    const stat = fs.statSync(file);
    if ((stat.mode & 0o077) !== 0) fs.chmodSync(file, 0o600);
    const value = JSON.parse(fs.readFileSync(file, "utf8")) as {
      version?: number;
      supabase_url?: string;
      refresh_token?: string;
    };
    if (value.version !== 1 || value.supabase_url !== supabaseUrl() || typeof value.refresh_token !== "string") {
      return null;
    }
    return { refreshToken: value.refresh_token };
  } catch {
    return null;
  }
}

export function remove(): void {
  try {
    fs.unlinkSync(locations().file);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
  }
}

export function credentialsPath(): string {
  return locations().file;
}
