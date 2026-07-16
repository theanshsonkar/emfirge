// Static search index for the ⌘K command menu, derived from the nav plus
// per-page keyword summaries so fuzzy search matches concepts, not just titles.
import { NAV } from "./nav";

const SUMMARY: Record<string, string> = {
  "/": "overview read-only mcp fork aws graph prove a fix seven tools git branch for your cloud",
  "/docs/quickstart": "install npx @emfirge/mcp read-only role first scan privacy mode getting started",
  "/docs/cli": "cli reference commands install privacy purge terminal npx",
  "/docs/faq": "faq simple common questions non technical what is emfirge safe read only free demo privacy scan time limits self hosting",
  "/docs/how-it-works": "clone mutate re-score diff graph 58 rules toxic combinations chokepoints attack paths deterministic",
  "/docs/graph": "one graph many answers graph model nodes edges resources typed edges exploit difficulty weights attack paths blast radius chokepoints betweenness centrality toxic combinations 58 rules scoring orphaned coverage how big scale honest limits",
  "/docs/privacy": "strict balanced off tokenization NAME tokens tokens.json redaction regulated",
  "/docs/security": "read-only iam role securityaudit externalid trust cloudformation permissions",
  "/docs/self-host": "self host docker environment variables trusted account external id on-prem",
  "/docs/tools": "seven mcp tools overview inputs outputs index",
  "/docs/tools/scan": "scan account overall risk score analysis_id findings region role_arn",
  "/docs/tools/get-findings": "findings severity critical moderate low mitre blast radius attack path",
  "/docs/tools/attack-paths": "attack paths chokepoints orphaned crown jewels centrality internet to data",
  "/docs/tools/verify-fix": "fork verify fix score before after safe to apply simulate delta toxic combos",
  "/docs/tools/simulate-breach": "kill chain breach what-if blast radius stages entry pivot impact",
  "/docs/tools/check-compliance": "cis aws 1.5 soc 2 controls compliance pass fail framework",
  "/docs/tools/setup-help": "cloudformation deploy role setup external id read-only",
};

export type SearchItem = {
  title: string;
  href: string;
  section: string;
  mono?: boolean;
  keywords: string;
};

export const SEARCH_ITEMS: SearchItem[] = NAV.flatMap((s) =>
  s.items.map((i) => ({
    title: i.title,
    href: i.href,
    section: s.label,
    mono: i.mono,
    keywords: SUMMARY[i.href] ?? "",
  })),
);
