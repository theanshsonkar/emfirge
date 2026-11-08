// Replace AWS IDs with tokens (SG_001, EC2_001, ...) before they hit the LLM.
// Mapping kept locally at ~/.emfirge/tokens.json.
// Modes via EMFIRGE_PRIVACY: strict (default), balanced, off.

import { homedir } from "node:os";
import { join } from "node:path";
import { readFileSync, existsSync } from "node:fs";
import { tightenIfOpen, writePrivateFile } from "./private-file.js";

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
  tightenIfOpen(TOKEN_DIR, 0o700);
  tightenIfOpen(TOKEN_FILE, 0o600);
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
    writePrivateFile(TOKEN_DIR, TOKEN_FILE, JSON.stringify(store, null, 2));
  } catch {
    // disk full or perms - in-memory tokens still work this session
  }
}

load();

function nextToken(prefix: string): string {
  store.counters[prefix] = (store.counters[prefix] ?? 0) + 1;
  return `${prefix}_${String(store.counters[prefix]).padStart(3, "0")}`;
}

function canonicalize(real: string): string {
  let match: RegExpMatchArray | null;
  match = real.match(/^arn:aws:iam::\d+:(?:role|user|policy)\/(.+)$/);
  if (match) return match[1];
  match = real.match(/^arn:aws:s3:::(.+)$/);
  if (match) return match[1].split("/")[0];
  match = real.match(/^arn:aws:lambda:[\w-]+:\d+:function:([^:]+)/);
  if (match) return match[1];
  match = real.match(/^arn:aws:dynamodb:[\w-]+:\d+:table\/([^/]+)/);
  if (match) return match[1];
  match = real.match(/^arn:aws:(?:sqs|sns):[\w-]+:\d+:([^:]+)$/);
  if (match) return match[1];
  match = real.match(/^arn:aws:ec2:[\w-]+:\d+:(?:instance|security-group|subnet|vpc)\/(.+)$/);
  if (match) return match[1];
  return real;
}

function tokenize(real: string, prefix: string): string {
  const existing = store.realToToken[real];
  if (existing) return existing;
  const canonical = canonicalize(real);
  const canonicalExisting = store.realToToken[canonical];
  if (canonicalExisting) {
    store.realToToken[real] = canonicalExisting;
    save();
    return canonicalExisting;
  }
  const token = nextToken(prefix);
  store.realToToken[canonical] = token;
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
  [/^arn:aws:dynamodb:[\w-]+:\d+:table\/.+$/, "DYNAMODB", true],
  [/^arn:aws:sqs:[\w-]+:\d+:.+$/, "SQS", true],
  [/^arn:aws:sns:[\w-]+:\d+:.+$/, "SNS", true],
  [/^arn:aws:scheduler:[\w-]+:\d+:schedule(?:-group)?\/.+$/, "SCHEDULER", true],
  [/^arn:aws:cloudfront::\d+:.+$/, "CLOUDFRONT", true],
  [/^arn:aws:wafv2:[\w-]+:\d+:.+$/, "WAFV2", true],

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
  [/arn:aws:dynamodb:[\w-]+:\d+:table\/[\w+=,.@\-/]+/g, "DYNAMODB", true],
  [/arn:aws:sqs:[\w-]+:\d+:[\w+=,.@\-]+/g, "SQS", true],
  [/arn:aws:sns:[\w-]+:\d+:[\w+=,.@\-]+/g, "SNS", true],
  [/arn:aws:scheduler:[\w-]+:\d+:schedule(?:-group)?\/[\w+=,.@\-/]+/g, "SCHEDULER", true],
  [/arn:aws:cloudfront::\d+:[\w+=,.@\-/]+/g, "CLOUDFRONT", true],
  [/arn:aws:wafv2:[\w-]+:\d+:[\w+=,.@\-/]+/g, "WAFV2", true],

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

  // A bare 12-digit AWS account id standing alone. Not part of a longer digit
  // run (timestamps, epoch ms), not glued to a word/hyphen/dot (versions, sg-...),
  // and not a decimal fraction. A trailing sentence period is fine. Runs last so
  // account ids inside ARNs are already consumed by the ARN patterns above.
  [/(?<![\w.-])\d{12}(?![\w-]|\.\d)/g, "ACCOUNT", true],
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
      if (name.length < 2 || isNeverSensitive(name)) return false;
      // Short tag values ("web", "dev") would garble ordinary words in prose;
      // the tag field itself is masked regardless.
      if (name.length < 4 && store.realToToken[name]?.startsWith("TAG_")) return false;
      // Skip values that are themselves AWS-pattern matches; those are
      // already handled by EMBEDDED_PATTERNS above.
      for (const [re] of PATTERNS) {
        if (re.test(name)) return false;
      }
      return true;
    })
    .sort((a, b) => b.length - a.length);

  for (const real of knownNames) {
    if (!out.includes(real) || isNeverSensitive(real)) continue;
    const token = store.realToToken[real];
    const escaped = real.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&");
    // Do not redact substrings of ordinary words or longer identifiers.
    out = out.replace(new RegExp(`(?<![A-Za-z0-9_-])${escaped}(?![A-Za-z0-9_-])`, "g"), token);
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
const NEVER_SENSITIVE_PATTERNS = [
  /^EMFIRGE-[A-Z0-9]+-\d{3}$/i,
  /^(?:cis-aws-1\.5|soc2)$/i,
  /^(?:\d+\.\d+|CC\d+\.\d+)$/i,
  /^T\d{4}(?:\.\d{3})?$/i,
  /^(?:critical|high|medium|low|info|informational|warning)$/i,
  /^(?:native|public|database)$/i,
  /^(?:ec2|s3|iam|rds|lambda|vpc|sg|sqs|sns|kms|cloudtrail|cloudwatch|guardduty|waf|ecs|elb|alb|api-gateway|secretsmanager|config)$/i,
  /^(?:instance|security[-_ ]?group|subnet|vpc|bucket|role|user|policy|function|database|volume|network[-_ ]?interface|route[-_ ]?table)$/i,
  /^(?:\d{1,5})$/,
  /^\*$/, // the default CloudFront behavior's path pattern
  /^(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/,
  // IPv6 CIDR ("::/0"): a range, like the IPv4 one above, not a host identifier
  /^(?=[0-9a-f:]*:)[0-9a-f:]+\/\d{1,3}$/i,
];

function isNeverSensitive(value: string, key = ""): boolean {
  if (NEVER_SENSITIVE_PATTERNS.some((re) => re.test(value))) return true;
  return /^(?:framework|control|section|compliance)/i.test(key) &&
    /^(?:[a-z][a-z0-9-]*|\d+(?:\.\d+)+|CC\d+(?:\.\d+)+)$/i.test(value);
}

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
  // CloudFront / Scheduler fields (also the field names under a branch diff's values)
  "aliases",
  "domain_name",
  "web_acl_id",
  "target_arn",
  "target_role_arn",
  "origin_access_control_id",
  "cache_policy_id",
  "origin_request_policy_id",
  "target_origin_id",
  "path_pattern",
  "s3_bucket",
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
  "recovery_resource_ids",
  "from",
  "to",
  "resources",
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

// Deep-walk that scrubs ONLY presigned-URL credentials, changing nothing else.
// Used for MODE="off", where the user has opted out of tokenizing their own
// resource names -- that is not consent to have access keys and session tokens
// echoed back through the tool channel.
function scrubCredentialsOnly(obj: unknown): unknown {
  if (obj == null) return obj;
  if (typeof obj === "string") return maskApiKeys(scrubPresignedUrls(obj));
  if (Array.isArray(obj)) return obj.map(scrubCredentialsOnly);
  if (typeof obj === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      out[k] = scrubCredentialsOnly(v);
    }
    return out;
  }
  return obj;
}

export function redactDeep(obj: unknown, parentKey = ""): unknown {
  if (MODE === "off") return scrubCredentialsOnly(obj);
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
    const str: string = maskApiKeys(obj); // never seed an API key into the token dictionary (it is written to disk)
    // Any whole-string AWS id (hex OR friendly-prefix) under ANY key: seed it
    // into the dictionary (typed, honoring balanced/generic) so narrative
    // strings referencing the same id later get scrubbed too.
    if (classifyStrict(str)) {
      tokenizeWholeId(str);
      return;
    }
    // Graph identifiers (node ids, attack_path elements, …): tokenize the whole
    // value even without an AWS-hex prefix, so captions/labels referencing the
    // same id later get scrubbed via the dictionary.
    if (IDENTIFIER_KEYS.has(parentKey)) {
      tokenizeIdentifier(str);
      return;
    }
    if (!SENSITIVE_KEYS.has(parentKey)) return;
    if (isNeverSensitive(str, parentKey) || str.length < 2) return;
    tokenize(str, "NAME");
    return;
  }

  if (Array.isArray(obj)) {
    for (const v of obj) collectNames(v, parentKey);
    return;
  }

  if (typeof obj === "object") {
    if (tagPairValueKey(obj as Record<string, unknown>, false) !== undefined) {
      collectTagValues(obj); // bare AWS {Key, Value} tag item
      return;
    }
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      if (isTagKey(k)) {
        collectTagValues(v);
        continue;
      }
      collectNames(v, k);
    }
  }
}


// ---------------------------------------------------------------------------
// Resource tags. Tag KEYS stay readable (owner, env, Name, aws:...); every tag
// VALUE is replaced by a token in strict and balanced mode, whatever it looks
// like -- owners, teams, cost centres and project names are the point of tags.
// Shapes handled: {k: v} maps, AWS [{Key, Value}] / [{key, value}] lists, and
// "k=v" strings, under any tag-ish key; plus bare AWS {Key, Value} pairs.
// The same value always gets the same token, and the token round-trips through
// expandTokens, so an agent can send it back in a tag-setting branch change.
// ---------------------------------------------------------------------------
const TAG_CONTAINER_KEYS = new Set(["tags", "tag", "tagset", "taglist", "resourcetags", "usertags"]);

function isTagKey(key: string): boolean {
  return TAG_CONTAINER_KEYS.has(key.toLowerCase().replace(/[-_]/g, ""));
}

function tagValueToken(real: string): string {
  if (real === "") return real;
  const masked = maskApiKeys(real);
  if (masked !== real) return masked; // an API key is never a tag value to remember (the store is written to disk)
  if (TOKEN_PATTERN.test(real) && store.tokenToReal[real] !== undefined) return real; // already issued
  const whole = tokenizeWholeId(real); // typed token when it is an id, so it matches the rest of the output
  if (whole !== null && whole !== real) return whole;
  return tokenize(real, "TAG");
}

const TAG_PAIR_EXTRAS = new Set(["propagate_at_launch", "PropagateAtLaunch", "ResourceId", "ResourceType"]);

// An AWS tag item: Key + Value (any one casing) and nothing but ASG extras.
function tagPairValueKey(o: Record<string, unknown>, allowLower: boolean): string | undefined {
  const upper = "Key" in o && "Value" in o;
  const lower = allowLower && "key" in o && "value" in o;
  if (!upper && !lower) return undefined;
  const keyName = upper ? "Key" : "key";
  const valueName = upper ? "Value" : "value";
  if (!Object.keys(o).every((k) => k === keyName || k === valueName || TAG_PAIR_EXTRAS.has(k))) return undefined;
  return valueName;
}

function maskTagLeaf(v: unknown): unknown {
  if (v == null) return v;
  if (typeof v === "string") return tagValueToken(v);
  if (typeof v === "number" || typeof v === "boolean") return tagValueToken(String(v));
  return maskTagValues(v);
}

// `v` is the content of a tags container (or a nested piece of one).
function maskTagValues(v: unknown): unknown {
  if (v == null) return v;
  if (typeof v === "string") {
    const eq = v.indexOf("=");
    return eq > 0 ? `${v.slice(0, eq + 1)}${tagValueToken(v.slice(eq + 1))}` : tagValueToken(v);
  }
  if (Array.isArray(v)) return v.map(maskTagValues);
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    const valueKey = tagPairValueKey(o, true);
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(o)) {
      out[k] = valueKey !== undefined ? (k === valueKey ? maskTagLeaf(val) : val) : maskTagLeaf(val);
    }
    return out;
  }
  return maskTagLeaf(v);
}

// Seed tag values into the dictionary so prose elsewhere in the same response
// ("owned by acme-payroll") is scrubbed too. Done by masking and discarding.
function collectTagValues(v: unknown): void {
  maskTagValues(v);
}

// Query parameters of a SigV4 presigned URL that carry credential material.
// A presigned URL is a bearer credential: X-Amz-Credential leads with the
// access-key id, X-Amz-Signature is the secret-derived proof, and
// X-Amz-Security-Token is a full STS session token. `emfirge_scan` returns a
// presigned report_url, so without this these values travel to the host LLM
// verbatim -- through the very layer whose job is catching exactly this shape.
const PRESIGNED_CREDENTIAL_PARAMS = new Set([
  "x-amz-credential",
  "x-amz-signature",
  "x-amz-security-token",
]);

// An Emfirge API key ("emf_" + 43 URL-safe characters). It is the user's own credential: it is shown only by the
// one command that makes it (`emfirge key create`, via the manifest's response.reveal, see cli/generic.ts) and is
// masked everywhere else, in every privacy mode including off. A cloud or CI agent that can see one can act as the user.
const API_KEY_PATTERN = /(?<![A-Za-z0-9])emf_[A-Za-z0-9_-]{16,}/g;
export const API_KEY_EXACT = /^emf_[A-Za-z0-9_-]{16,}$/;

export function maskApiKeys(value: string): string {
  return value.includes("emf_") ? value.replace(API_KEY_PATTERN, "emf_REDACTED") : value;
}

// Replace credential-bearing query values in any URL inside `value`, leaving
// the rest of the URL (host, path, expiry) intact so it stays diagnosable.
// Deliberately NOT gated on MODE: an access key is not a resource name the
// user might reasonably want un-tokenized, and privacy=off is a choice to see
// your own resource ids, not a request to have credentials echoed back.
export function scrubPresignedUrls(value: string): string {
  if (!value.includes("X-Amz-")) return value;
  return value.replace(/https?:\/\/[^\s"'<>]+/g, (url) => {
    const q = url.indexOf("?");
    if (q === -1) return url;
    const base = url.slice(0, q);
    const scrubbed = url
      .slice(q + 1)
      .split("&")
      .map((pair) => {
        const eq = pair.indexOf("=");
        if (eq === -1) return pair;
        const key = pair.slice(0, eq);
        return PRESIGNED_CREDENTIAL_PARAMS.has(key.toLowerCase())
          ? `${key}=REDACTED`
          : pair;
      })
      .join("&");
    return `${base}?${scrubbed}`;
  });
}

// A branch diff's `values`: { "base.<field>": { before, after } }. The wrapper
// keys (before/after) say nothing about the value, so the FIELD name decides how
// it is masked (aliases, web_acl_id, target_arn, ...). Nested objects (origins,
// behaviors) are then walked with their own keys as usual.
function isDiffValues(v: unknown): v is Record<string, Record<string, unknown>> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const entries = Object.values(v as Record<string, unknown>);
  return entries.length > 0 && entries.every(
    (e) => e !== null && typeof e === "object" && !Array.isArray(e) && "before" in e && "after" in e,
  );
}

function redactDiffValues(v: Record<string, Record<string, unknown>>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, change] of Object.entries(v)) {
    const field = key.slice(key.lastIndexOf(".") + 1);
    const masked: Record<string, unknown> = {};
    for (const [side, value] of Object.entries(change)) {
      masked[side] = redactDeepInner(value, side === "before" || side === "after" ? field : side);
    }
    out[key] = masked;
  }
  return out;
}

function redactDeepInner(obj: unknown, parentKey = ""): unknown {
  if (MODE === "off") return obj;
  if (obj == null) return obj;

  if (typeof obj === "string") {
    // 0. Strip credential material out of any presigned URL first, whatever
    //    key it arrived under. Runs before the id rules because the URL's own
    //    host/path may also contain a bucket name those rules then tokenize.
    //    Bound to a typed local rather than reassigning `obj`, which is
    //    declared `unknown` and would lose its narrowing.
    const text: string = maskApiKeys(scrubPresignedUrls(obj));
    if (isNeverSensitive(text, parentKey) || text === "emf_REDACTED") return text;
    // 1. Whole-string AWS id (hex OR friendly-prefix) under ANY key — single
    //    typed token (honors balanced/off/generic). Catches vpc_id, allocation_id,
    //    flow_logs[] entries, etc., not just fields we enumerate.
    const whole = tokenizeWholeId(text);
    if (whole !== null) return whole;
    // 2. Graph identifier key — tokenize the id even without AWS-hex format
    //    (friendly node ids: "acme-prod-customers", "iam-role-AppServerRole").
    if (IDENTIFIER_KEYS.has(parentKey)) {
      return tokenizeIdentifier(text);
    }
    // 3. Graph label "<Type>: <name>" — scrub the name half.
    if (parentKey === "label") {
      return redactLabel(text);
    }
    // 4. Sensitive key — tokenize the whole value as a name.
    if (SENSITIVE_KEYS.has(parentKey)) {
      return isNeverSensitive(text, parentKey) ? text : tokenize(text, "NAME");
    }
    // 5. Free-text — scan for embedded AWS IDs + known names (narrative captions)
    return redactEmbedded(text);
  }

  if (Array.isArray(obj)) {
    return obj.map((v) => redactDeepInner(v, parentKey));
  }

  if (typeof obj === "object") {
    if (tagPairValueKey(obj as Record<string, unknown>, false) !== undefined) {
      return maskTagValues(obj); // bare AWS {Key, Value} tag item
    }
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      if (isTagKey(k)) {
        out[k] = maskTagValues(v);
      } else if (k === "values" && isDiffValues(v)) {
        out[k] = redactDiffValues(v);
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
