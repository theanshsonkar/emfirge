import type { NextConfig } from "next";

// emfirge.cloud serves two things from one Next app:
//  1. the website (pages under src/app, plus the generated .md files and llms.txt in public/), and
//  2. a proxy: /api/* goes to the backend. The CLI and the MCP adapter call https://emfirge.cloud/api, so this must keep working.
// The proxy needs a normal (non-export) Next build, so there is no `output: "export"`.
const backendUrl = process.env.EMFIRGE_BACKEND_URL ?? "http://localhost:3000";

// Old docs site (emfirge-docs, before the new site replaced it) -> the page that now answers the same question.
// All permanent (308). A trailing slash on the old URL (/docs/tool-scan/) matches too.
const MCP = "/cli/#mcp-adapter";
const OLD_TOOLS = [
  "setup-help", "login", "logout", "link-project", "scan", "get-findings", "attack-paths", "simulate-breach", "verify-fix",
  "check-compliance", "create-branch", "get-branch", "fork-branch", "apply-change", "list-branches", "rollback-branch",
  "rollback-branch-to-count", "discard-branch", "branch-diff", "branch-verdict", "compare-branches", "plan-verdict",
  "branch-handback", "in-use-evidence", "policy-checks",
];
const OLD_DOCS: Record<string, string> = {
  // old path -> new path
  "/docs": "/",
  "/docs/quickstart": "/quickstart/",
  "/docs/concepts": "/how-it-works/",
  "/docs/branches": "/how-it-works/",
  "/docs/changes": "/how-it-works/",
  "/docs/diffs": "/how-it-works/",
  "/docs/plans": "/how-it-works/",
  "/docs/graph": "/how-it-works/",
  "/docs/how-it-works": "/how-it-works/",
  "/docs/lenses": "/coverage/",
  "/docs/safety": "/security/",
  "/docs/privacy": "/security/",
  "/docs/security": "/security/",
  "/docs/mcp": MCP,
  "/docs/cli": "/cli/",
  "/docs/configuration": "/cli/#global", // EMFIRGE_BASE_URL, EMFIRGE_PRIVACY, EMFIRGE_API_KEY
  "/docs/self-host": "/cli/#global", // self-hosting = pointing the client at your backend with EMFIRGE_BASE_URL
  "/docs/troubleshooting": "/faq/#troubleshooting",
  "/docs/glossary": "/faq/#glossary",
  "/docs/faq": "/faq/",
  ...Object.fromEntries(OLD_TOOLS.map((t) => [`/docs/tool-${t}`, MCP])),
  // other old URLs: the old connect page, and links the repo's code printed (mcp/src/tools/setup.ts)
  "/connect": "/quickstart/",
  "/security.html": "/security/",
  "/guide": "/cli/", // docs.emfirge.cloud/guide appears in an MCP test fixture; `emfirge guide` is a CLI command, documented there
};

const nextConfig: NextConfig = {
  trailingSlash: true,
  // With trailingSlash on, Next would 308 /api/project to /api/project/ before the rewrite runs. The CLI, MCP and the deploy
  // health check call /api/... without a slash, so skip that automatic redirect. A page URL without a slash (/quickstart) then
  // serves the page directly; each page's <link rel="canonical"> points at the slash form.
  skipTrailingSlashRedirect: true,
  images: { unoptimized: true },
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${backendUrl}/:path*` }];
  },
  async redirects() {
    return Object.entries(OLD_DOCS).map(([source, destination]) => ({ source, destination, permanent: true }));
  },
};

export default nextConfig;
