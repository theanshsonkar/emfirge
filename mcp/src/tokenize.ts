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

// Friendly / label-style identifiers that carry a known AWS prefix but NOT the
// hex body EMBEDDED_PATTERNS require. In real accounts these are hex ids; in
// graph node ids (and demo data) they're human strings — "sg-backend",
// "subnet-priv-a", "iam-role-AppServerRole". Same [prefix, redact-in-balanced]
// contract as PATTERNS, so balanced mode keeps generic topology (subnet/vpc/…)
// raw. Only used for values we already KNOW are identifiers (under an
// IDENTIFIER_KEY or the name-half of a "<Type>: <name>" label) — never for
// arbitrary prose, so a loose prefix here can't false-match normal words.
const PREFIX_TYPES: Array<[RegExp, string, boolean]> = [
  [/^iam-role-.+$/i, "IAM_ROLE", true],
  [/^sg-.+$/i, "SG", true],
  [/^i-.+$/i, "EC2", true],
  [/^eipalloc-.+$/i, "EIP", true],
  [/^vol-.+$/i, "VOL", false],
  [/^subnet-.+$/i, "SUBNET", false],
  [/^vpc-.+$/i, "VPC", false],
  [/^eni-.+$/i, "ENI", false],
  [/^rtb-.+$/i, "RTB", false],
  [/^igw-.+$/i, "IGW", false],
  [/^nat-.+$/i, "NAT", false],
  [/^acl-.+$/i, "ACL", false],
];

// Graph nodes that are concepts, not resources — never tokenize (would turn
// readable attack narratives into gibberish and pollute the token map).
const GENERIC_NODE_IDS = new Set(["INTERNET", "Internet", "internet"]);

// Backend graph labels follow the convention "<TypeLabel>: <name>" — e.g.
// "IAM Role: AppServerRole", "SG: backend-private-sg", "RDS: acme-prod-customers".
// The <name> half can be a friendly name that never appears as a bare node id
// (an IAM role's profile name, an SG's Name tag), so it can ONLY be caught by
// parsing this convention out of captions/labels. The type word itself is
// generic (kept verbatim). Longest first so "IAM Role" wins over "IAM", etc.
const TYPE_LABELS = [
  "Security Group",
  "API Gateway",
  "IAM Role",
  "CloudFront",
  "API GW",
  "Subnet",
  "Secret",
  "Cache",
  "RDS",
  "EC2",
  "SG",
  "S3",
  "LB",
  "VPC",
  "IAM",
  "EBS",
  "EIP",
];

// Decide how to tokenize a value we KNOW is an identifier (it sits under an
// IDENTIFIER_KEY, or is the <name> half of a "<Type>: <name>" label).
// Order: exact AWS-format PATTERNS (typed) -> loose AWS prefixes -> NAME.
//
// classifyStrict returns null when the value isn't id-SHAPED (so callers can
// tell "this is an id" from "this is an arbitrary name"). classifyIdentifier
// adds the NAME fallback for values we already know are identifiers.
function classifyStrict(real: string): [string, boolean] | null {
  for (const [re, prefix, balancedRedact] of PATTERNS) {
    if (re.test(real)) return [prefix, balancedRedact];
  }
  for (const [re, prefix, balancedRedact] of PREFIX_TYPES) {
    if (re.test(real)) return [prefix, balancedRedact];
  }
  return null;
}

function classifyIdentifier(real: string): [string, boolean] {
  return classifyStrict(real) ?? ["NAME", true]; // else a plain name (bucket/role/secret)
}

// Tokenize a value that IS a whole AWS identifier (hex OR friendly-prefix),
// wherever it appears — including under arbitrary keys like vpc_id,
// allocation_id, flow_logs[]. Returns:
//   • a token string        — it's an id and we redacted it
//   • the value unchanged    — it's an id we intentionally keep raw
//                              (off mode, generic node, or generic topology in
//                              balanced) — still "handled", don't fall through
//   • null                   — not id-shaped; let the caller decide
function tokenizeWholeId(real: string): string | null {
  const cls = classifyStrict(real);
  if (!cls) return null;
  if (MODE === "off") return real;
  if (GENERIC_NODE_IDS.has(real)) return real;
  const [prefix, balancedRedact] = cls;
  if (MODE === "balanced" && !balancedRedact) return real;
  return tokenize(real, prefix);
}

// Tokenize a value known to be an identifier. Honors mode + the balanced-mode
// redaction flag. Returns the value unchanged when it must stay raw: off mode,
// a generic node ("INTERNET"), an already-issued token, or generic topology
// (subnet/vpc/vol/…) in balanced mode.
function tokenizeIdentifier(real: string): string {
  if (MODE === "off") return real;
  if (real.length < 2) return real;
  if (GENERIC_NODE_IDS.has(real)) return real;
  if (TOKEN_PATTERN.test(real)) return real; // already a token — don't re-wrap
  const [prefix, balancedRedact] = classifyIdentifier(real);
  if (MODE === "balanced" && !balancedRedact) return real;
  return tokenize(real, prefix);
}

// The <name> half of a "<Type>: <name>" label. Skips already-issued tokens and
// leaves purely descriptive labels (sizes like "50GB") readable, but still
// tokenizes real identifiers (names, ids, IPs).
function tokenizeLabelName(name: string): string {
  if (TOKEN_PATTERN.test(name)) return name;
  const [prefix] = classifyIdentifier(name);
  if (prefix === "NAME" && /^[\d.]+\s?[A-Za-z]{0,3}$/.test(name)) return name;
  return tokenizeIdentifier(name);
}

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

  // Backend label convention "<Type>: <name>" inside narrative captions
  // (e.g. "… assumes IAM Role: AppServerRole …", "… via SG: backend-private-sg").
  // The <name> half is frequently a friendly name that is NOT a bare node id,
  // so the dictionary pass above can't catch it. \b anchors the type word so
  // "SG:" won't match inside "MSG:". The name run stops at whitespace, which is
  // correct for the single-token names captions use; multi-word label *fields*
  // are handled wholesale by redactLabel().
  for (const label of TYPE_LABELS) {
    const esc = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(`(\\b${esc}:\\s*)([A-Za-z0-9][\\w./-]*)`, "g");
    out = out.replace(re, (_m, pre: string, name: string) => pre + tokenizeLabelName(name));
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

// keys whose values are graph identifiers — often friendly / label-style node
// ids that are NOT AWS-hex format and never sit under a SENSITIVE_KEY, so they
// used to pass straight through to the LLM (this was the leak):
//   attack_path[], node_ids[], path[], node_id, resource_ids[], from/to, …
// We tokenize the whole value, typed by prefix where known (SG_/EC2_/IAM_ROLE_
// /SUBNET_…) and NAME_ otherwise. Arrays inherit their parent key, so every
// element of attack_path / node_ids is covered.
const IDENTIFIER_KEYS = new Set([
  "node_id",
  "node_ids",
  "affected_node_ids",
  "attack_path",
  "path",
  "resource_ids",
  "from",
  "to",
  "source",
  "target",
]);

// A "label" field is exactly "<Type>: <name>" (e.g. "API GW: Internal Admin API",
// "EIP: 52.20.14.202"). Tokenize the whole <name> half — handles multi-word
// names and embedded IPs that the caption regex (single-token) would miss —
// while keeping the generic type word and descriptive sizes ("EBS: 50GB") readable.
function redactLabel(s: string): string {
  if (MODE === "off") return s;
  const idx = s.indexOf(": ");
  if (idx > 0 && idx <= 20) {
    const type = s.slice(0, idx);
    const name = s.slice(idx + 2);
    if (TYPE_LABELS.includes(type)) {
      const scrubbed = tokenizeLabelName(name);
      if (scrubbed !== name) return `${type}: ${scrubbed}`;
    }
  }
  // Not the expected convention — fall back to free-text scrubbing.
  return redactEmbedded(s);
}

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
    // Any whole-string AWS id (hex OR friendly-prefix) under ANY key: seed it
    // into the dictionary (typed, honoring balanced/generic) so narrative
    // strings referencing the same id later get scrubbed too.
    if (classifyStrict(obj)) {
      tokenizeWholeId(obj);
      return;
    }
    // Graph identifiers (node ids, attack_path elements, …): tokenize the whole
    // value even without an AWS-hex prefix, so captions/labels referencing the
    // same id later get scrubbed via the dictionary.
    if (IDENTIFIER_KEYS.has(parentKey)) {
      tokenizeIdentifier(obj);
      return;
    }
    if (!SENSITIVE_KEYS.has(parentKey)) return;
    if (obj.length < 4) return;
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
    // 1. Whole-string AWS id (hex OR friendly-prefix) under ANY key — single
    //    typed token (honors balanced/off/generic). Catches vpc_id, allocation_id,
    //    flow_logs[] entries, etc., not just fields we enumerate.
    const whole = tokenizeWholeId(obj);
    if (whole !== null) return whole;
    // 2. Graph identifier key — tokenize the id even without AWS-hex format
    //    (friendly node ids: "acme-prod-customers", "iam-role-AppServerRole").
    if (IDENTIFIER_KEYS.has(parentKey)) {
      return tokenizeIdentifier(obj);
    }
    // 3. Graph label "<Type>: <name>" — scrub the name half.
    if (parentKey === "label") {
      return redactLabel(obj);
    }
    // 4. Sensitive key — tokenize the whole value as a name.
    if (SENSITIVE_KEYS.has(parentKey)) {
      return tokenize(obj, "NAME");
    }
    // 5. Free-text — scan for embedded AWS IDs + known names (narrative captions)
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
