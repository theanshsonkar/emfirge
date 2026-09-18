// Single source of truth for the docs sidebar, breadcrumbs, and prev/next.
export type NavLink = { title: string; href: string; mono?: boolean };
export type NavSection = { label: string; items: NavLink[] };

export const NAV: NavSection[] = [
  {
    label: "Get Started",
    items: [
      { title: "Overview", href: "/" },
      { title: "Quickstart", href: "/docs/quickstart" },
      { title: "CLI reference", href: "/docs/cli" },
      { title: "FAQ", href: "/docs/faq" },
    ],
  },
  {
    label: "Concepts",
    items: [
      { title: "One graph, many answers", href: "/docs/graph" },
      { title: "How the fork works", href: "/docs/how-it-works" },
    ],
  },
  {
    label: "Privacy & Trust",
    items: [
      { title: "Privacy modes", href: "/docs/privacy" },
      { title: "Security model", href: "/docs/security" },
      { title: "Self-hosting", href: "/docs/self-host" },
    ],
  },
  {
    label: "MCP Tools",
    items: [{ title: "Overview", href: "/docs/tools" }],
  },
  {
    label: "Analyze",
    items: [
      { title: "emfirge_scan", href: "/docs/tools/scan", mono: true },
      { title: "emfirge_get_findings", href: "/docs/tools/get-findings", mono: true },
      { title: "emfirge_attack_paths", href: "/docs/tools/attack-paths", mono: true },
      { title: "emfirge_simulate_breach", href: "/docs/tools/simulate-breach", mono: true },
      { title: "emfirge_verify_fix", href: "/docs/tools/verify-fix", mono: true },
      { title: "emfirge_check_compliance", href: "/docs/tools/check-compliance", mono: true },
    ],
  },
  {
    label: "Branch",
    items: [
      { title: "emfirge_create_branch", href: "/docs/tools/create-branch", mono: true },
      { title: "emfirge_apply_change", href: "/docs/tools/apply-change", mono: true },
      { title: "emfirge_branch_diff", href: "/docs/tools/branch-diff", mono: true },
      { title: "emfirge_branch_verdict", href: "/docs/tools/branch-verdict", mono: true },
      { title: "emfirge_rollback_branch", href: "/docs/tools/rollback-branch", mono: true },
      { title: "emfirge_discard_branch", href: "/docs/tools/discard-branch", mono: true },
      { title: "emfirge_list_branches", href: "/docs/tools/list-branches", mono: true },
      { title: "emfirge_compare_branches", href: "/docs/tools/compare-branches", mono: true },
    ],
  },
  {
    label: "Setup",
    items: [{ title: "emfirge_setup_help", href: "/docs/tools/setup-help", mono: true }],
  },
];

// Flattened order for prev/next navigation.
export const FLAT: NavLink[] = NAV.flatMap((s) => s.items);

export function prevNext(pathname: string): { prev?: NavLink; next?: NavLink } {
  const i = FLAT.findIndex((l) => l.href === pathname);
  if (i === -1) return {};
  return { prev: FLAT[i - 1], next: FLAT[i + 1] };
}
