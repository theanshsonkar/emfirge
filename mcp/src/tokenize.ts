// Replace AWS IDs with tokens (SG_001, EC2_001, ...) before they hit the LLM.
// Mapping kept locally at ~/.emfirge/tokens.json.
// Modes via EMFIRGE_PRIVACY: strict (default), balanced, off.

import { homedir } from "node:os";
import { join } from "node:path";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";

export type PrivacyMode = "strict" | "balanced" | "off";

const RAW_MODE = (process.env.EMFIRGE_PRIVACY ?? "strict").toLowerCase();
const MODE: PrivacyMode = (["strict", "balanced", "off"] as const).includes(RAW_MODE as PrivacyMode)
  ? (RAW_MODE as PrivacyMode)
  : "strict";

const TOKEN_DIR = join(homedir(), ".emfirge");
const TOKEN_FILE = join(TOKEN_DIR, "tokens.json");

interface TokenStore {
  realToToken: Record<string, string>;
  tokenToReal: Record<string, string>;
  counters: Record<string, number>;
}

let store: TokenStore = { realToToken: {}, tokenToReal: {}, counters: {} };

function load(): void {
  if (!existsSync(TOKEN_FILE)) return;
  try {
    const data = JSON.parse(readFileSync(TOKEN_FILE, "utf-8"));
    if (data && typeof data === "object") {
      store = {
        realToToken: data.realToToken ?? {},
        tokenToReal: data.tokenToReal ?? {},
        counters: data.counters ?? {},
      };
    }
  } catch {
    // corrupt file, start fresh
  }
}

function save(): void {
  try {
    if (!existsSync(TOKEN_DIR)) mkdirSync(TOKEN_DIR, { recursive: true });
    writeFileSync(TOKEN_FILE, JSON.stringify(store, null, 2));
  } catch {
    // disk full or perms - in-memory tokens still work this session
  }
}

load();

function nextToken(prefix: string): string {
  store.counters[prefix] = (store.counters[prefix] ?? 0) + 1;
  return `${prefix}_${String(store.counters[prefix]).padStart(3, "0")}`;
}

function tokenize(real: string, prefix: string): string {
  const existing = store.realToToken[real];
  if (existing) return existing;
  const token = nextToken(prefix);
  store.realToToken[real] = token;
  store.tokenToReal[token] = real;
  save();
  return token;
}

export function detokenize(token: string): string {
  return store.tokenToReal[token] ?? token;
}

// pattern, prefix, redact-in-balanced-mode
const PATTERNS: Array<[RegExp, string, boolean]> = [
  [/^arn:aws:iam::\d+:role\/.+$/, "IAM_ROLE", true],
  [/^arn:aws:iam::\d+:user\/.+$/, "IAM_USER", true],
  [/^arn:aws:iam::\d+:policy\/.+$/, "IAM_POLICY", true],
  [/^arn:aws:secretsmanager:[\w-]+:\d+:secret:.+$/, "SECRET", true],
  [/^arn:aws:lambda:[\w-]+:\d+:function:.+$/, "LAMBDA", true],
  [/^arn:aws:rds:[\w-]+:\d+:db:.+$/, "RDS", true],
  [/^arn:aws:s3:::.+$/, "S3", true],
  [/^arn:aws:kms:[\w-]+:\d+:key\/.+$/, "KMS", true],

  [/^sg-[a-f0-9]+$/i, "SG", true],
  [/^i-[a-f0-9]+$/i, "EC2", true],
  [/^eipalloc-[a-f0-9]+$/i, "EIP", true],

  // less sensitive - only redact in strict
  [/^vol-[a-f0-9]+$/i, "VOL", false],
  [/^subnet-[a-f0-9]+$/i, "SUBNET", false],
  [/^vpc-[a-f0-9]+$/i, "VPC", false],
  [/^eni-[a-f0-9]+$/i, "ENI", false],
  [/^rtb-[a-f0-9]+$/i, "RTB", false],
  [/^igw-[a-f0-9]+$/i, "IGW", false],
  [/^nat-[a-f0-9]+$/i, "NAT", false],
  [/^acl-[a-f0-9]+$/i, "ACL", false],

  [/^\d{12}$/, "ACCOUNT", true],
  [/^(?:\d{1,3}\.){3}\d{1,3}$/, "IP", true],
];

// Unanchored versions for scanning IDs embedded inside narrative strings
// (e.g. "Attacker lands on EC2: i-0c0c... via SG"). Only patterns with
// distinctive prefixes are safe to unanchor — pure 12-digit numbers and IPs
// would false-match version strings, ports, etc., so they're excluded here
// and only redacted as whole-string values via PATTERNS.
const EMBEDDED_PATTERNS: Array<[RegExp, string, boolean]> = [
  // ARNs are unambiguous; \S+ stops at whitespace so a sentence boundary works
  [/arn:aws:iam::\d+:role\/[\w+=,.@\-/]+/g, "IAM_ROLE", true],
  [/arn:aws:iam::\d+:user\/[\w+=,.@\-/]+/g, "IAM_USER", true],
  [/arn:aws:iam::\d+:policy\/[\w+=,.@\-/]+/g, "IAM_POLICY", true],
  [/arn:aws:secretsmanager:[\w-]+:\d+:secret:[\w+=,.@\-/]+/g, "SECRET", true],
  [/arn:aws:lambda:[\w-]+:\d+:function:[\w+=,.@\-/]+/g, "LAMBDA", true],
  [/arn:aws:rds:[\w-]+:\d+:db:[\w+=,.@\-/]+/g, "RDS", true],
  [/arn:aws:kms:[\w-]+:\d+:key\/[\w+=,.@\-/]+/g, "KMS", true],
  // S3 ARNs (arn:aws:s3:::bucket[/key]). Missing here previously, which let
  // bucket ARNs leak when they appeared inside narrative captions rather than
  // as a standalone field value.
  [/arn:aws:s3:::[\w.\-/]+/g, "S3", true],

  // Resource IDs: word boundary on both sides + the AWS prefix is enough
  [/\bsg-[a-f0-9]{8,}\b/gi, "SG", true],
  [/\bi-[a-f0-9]{8,}\b/gi, "EC2", true],
  [/\beipalloc-[a-f0-9]{8,}\b/gi, "EIP", true],
  [/\bvol-[a-f0-9]{8,}\b/gi, "VOL", false],
  [/\bsubnet-[a-f0-9]{8,}\b/gi, "SUBNET", false],
  [/\bvpc-[a-f0-9]{8,}\b/gi, "VPC", false],
  [/\beni-[a-f0-9]{8,}\b/gi, "ENI", false],
  [/\brtb-[a-f0-9]{8,}\b/gi, "RTB", false],
  [/\bigw-[a-f0-9]{8,}\b/gi, "IGW", false],
  [/\bnat-[a-f0-9]{8,}\b/gi, "NAT", false],
  [/\bacl-[a-f0-9]{8,}\b/gi, "ACL", false],
];

function redactString(s: string): string {
  if (MODE === "off") return s;
  for (const [re, prefix, balancedRedact] of PATTERNS) {
    if (re.test(s)) {
      if (MODE === "balanced" && !balancedRedact) return s;
      return tokenize(s, prefix);
    }
  }
  return s;
}

// Scan a free-text string for AWS IDs anywhere inside it and replace
// each match with a token. Used for narrative captions / summaries / etc.
//
// Two passes:
//   1. AWS-prefix patterns (sg-, i-, arn:aws:..., etc.)
//   2. Known names already in the store (collected by collectNames() during
//      the pre-walk in redactDeep). This catches things like IAM user names
//      and S3 bucket names that appear mid-sentence in LLM narratives but
//      have no prefix to anchor on.
function redactEmbedded(s: string): string {
  if (MODE === "off") return s;
  let out = s;

  for (const [re, prefix, balancedRedact] of EMBEDDED_PATTERNS) {
    if (MODE === "balanced" && !balancedRedact) continue;
    out = out.replace(re, (match) => tokenize(match, prefix));
  }

  // Known names from the dictionary — sorted by length descending so longer
  // names match first (avoids "emfirge" matching inside "emfirge-reports").
  const knownNames = Object.keys(store.realToToken)
    .filter((name) => {
      if (name.length < 4) return false;
      // Skip values that are themselves AWS-pattern matches; those are
      // already handled by EMBEDDED_PATTERNS above.
      for (const [re] of PATTERNS) {
        if (re.test(name)) return false;
      }
      return true;
    })
    .sort((a, b) => b.length - a.length);

  for (const real of knownNames) {
    if (!out.includes(real)) continue;
    const token = store.realToToken[real];
    const escaped = real.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&");
    out = out.replace(new RegExp(escaped, "g"), token);
  }

  return out;
}

// keys whose values we tokenize even if the value isn't a known ID pattern
// (bucket names, role names - arbitrary strings that still leak intent)
const SENSITIVE_KEYS = new Set([
  "resource_id",
  "id",
  "arn",
  "name",
  "bucket_name",
  "function_name",
  "role_name",
  "user_name",
  "role_arn",
  "user_arn",
  "policy_arn",
  "instance_profile_arn",
  "secret_arn",
  "topic_arn",
  "queue_arn",
  "key_arn",
  "account_id",
  "aws_account_id",
  "public_ip",
  "private_ip",
  "ip_address",
]);

export function redactDeep(obj: unknown, parentKey = ""): unknown {
  if (MODE === "off") return obj;
  // First pass at the top level: pre-tokenize every value found under a
  // SENSITIVE_KEY so embedded scans below have the full name dictionary.
  // Without this, narrative strings like "User ansh-admin has stale keys"
  // leak the name because the user_name field is visited later in traversal.
  if (parentKey === "") collectNames(obj);
  return redactDeepInner(obj, parentKey);
}

// Pre-walk: tokenize every value under a SENSITIVE_KEY into the store
// without modifying the object. Read-only side effect on `store`.
function collectNames(obj: unknown, parentKey = ""): void {
  if (MODE === "off") return;
  if (obj == null) return;

  if (typeof obj === "string") {
    if (!SENSITIVE_KEYS.has(parentKey)) return;
    if (obj.length < 4) return;
    // If it already matches a pattern (e.g. arn:..., sg-...), leave it for
    // PATTERNS to handle so it gets the right prefix instead of "NAME".
    for (const [re] of PATTERNS) {
      if (re.test(obj)) return;
    }
    tokenize(obj, "NAME");
    return;
  }

  if (Array.isArray(obj)) {
    for (const v of obj) collectNames(v, parentKey);
    return;
  }

  if (typeof obj === "object") {
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      const childKey = k === "tags" || k === "Tags" ? "name" : k;
      collectNames(v, childKey);
    }
  }
}

function redactDeepInner(obj: unknown, parentKey = ""): unknown {
  if (MODE === "off") return obj;
  if (obj == null) return obj;

  if (typeof obj === "string") {
    // 1. Whole-string match — return a single token
    for (const [re] of PATTERNS) {
      if (re.test(obj)) return redactString(obj);
    }
    // 2. Sensitive key — tokenize the whole value as a name
    if (SENSITIVE_KEYS.has(parentKey)) {
      return tokenize(obj, "NAME");
    }
    // 3. Free-text — scan for embedded AWS IDs (e.g. narrative captions)
    return redactEmbedded(obj);
  }

  if (Array.isArray(obj)) {
    return obj.map((v) => redactDeepInner(v, parentKey));
  }

  if (typeof obj === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      if (k === "tags" || k === "Tags") {
        out[k] = redactDeepInner(v, "name");
      } else {
        out[k] = redactDeepInner(v, k);
      }
    }
    return out;
  }

  return obj;
}

// Token prefixes can contain digits (EC2, S3), so the char class must allow
// 0-9 — otherwise EC2_001 / S3_001 never match and expandTokens silently
// leaves them unresolved, sending the literal token to the backend.
const TOKEN_PATTERN = /^[A-Z0-9_]+_\d{3}$/;

// inverse of redactDeep: swap tokens back to real IDs before sending to backend
export function expandTokens(obj: unknown): unknown {
  if (obj == null) return obj;

  if (typeof obj === "string") {
    if (TOKEN_PATTERN.test(obj)) return detokenize(obj);
    return obj.replace(/\b[A-Z0-9_]+_\d{3}\b/g, (match) => detokenize(match));
  }

  if (Array.isArray(obj)) {
    return obj.map(expandTokens);
  }

  if (typeof obj === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      out[k] = expandTokens(v);
    }
    return out;
  }

  return obj;
}

export function privacyMode(): PrivacyMode {
  return MODE;
}

export function tokenStorePath(): string {
  return TOKEN_FILE;
}

export function clearTokenStore(): void {
  store = { realToToken: {}, tokenToReal: {}, counters: {} };
  save();
}

export function listTokens(): Array<{ token: string; real: string }> {
  return Object.entries(store.tokenToReal).map(([token, real]) => ({ token, real }));
}
