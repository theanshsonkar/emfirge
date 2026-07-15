// Single source of truth for the docs sidebar, breadcrumbs, and prev/next.
export type NavLink = { title: string; href: string; mono?: boolean };
export type NavSection = { label: string; items: NavLink[] };

export const NAV: NavSection[] = [
  {
    label: "Get Started",
    items: [
      { title: "Overview", href: "/docs" },
      { title: "Quickstart", href: "/docs/quickstart" },
      { title: "CLI reference", href: "/docs/cli" },
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
    items: [
      { title: "Overview", href: "/docs/tools" },
      { title: "emfirge_scan", href: "/docs/tools/scan", mono: true },
      { title: "emfirge_get_findings", href: "/docs/tools/get-findings", mono: true },
      { title: "emfirge_attack_paths", href: "/docs/tools/attack-paths", mono: true },
      { title: "emfirge_verify_fix", href: "/docs/tools/verify-fix", mono: true },
      { title: "emfirge_simulate_breach", href: "/docs/tools/simulate-breach", mono: true },
      { title: "emfirge_check_compliance", href: "/docs/tools/check-compliance", mono: true },
      { title: "emfirge_setup_help", href: "/docs/tools/setup-help", mono: true },
    ],
  },
];

// Flattened order for prev/next navigation.
export const FLAT: NavLink[] = NAV.flatMap((s) => s.items);

export function prevNext(pathname: string): { prev?: NavLink; next?: NavLink } {
  const i = FLAT.findIndex((l) => l.href === pathname);
  if (i === -1) return {};
  return { prev: FLAT[i - 1], next: FLAT[i + 1] };
}
