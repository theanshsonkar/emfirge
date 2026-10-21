import { documents } from "./content";

const item = (label: string, href: string) => ({ label, href: `/docs/${href}` });
export const docsNav = [
  {label:"Getting started",items:[{label:"Overview",href:"/"},item("Developer quickstart","quickstart"),item("How the fork works","how-it-works")]},
  {label:"Concepts",items:[item("Key concepts","concepts"),item("Create and compare branches","branches"),item("Apply changes","changes"),item("Read diffs and verdicts","diffs"),item("Plans and hand-back","plans"),item("Lenses and coverage","lenses"),item("The infrastructure graph","graph")]},
  {label:"Safety & privacy",items:[item("Safety and model limits","safety"),item("Privacy modes","privacy"),item("Security model","security")]},
  {label:"MCP tools",collapsible:true,items:[item("MCP tool reference","mcp"),item("Setup help","tool-setup-help"),item("Login","tool-login"),item("Logout","tool-logout"),item("Link project","tool-link-project"),item("Scan","tool-scan"),item("Get findings","tool-get-findings"),item("Attack paths","tool-attack-paths"),item("Simulate breach","tool-simulate-breach"),item("Verify fix","tool-verify-fix"),item("Check compliance","tool-check-compliance"),item("Create branch","tool-create-branch"),item("Get branch","tool-get-branch"),item("Fork branch","tool-fork-branch"),item("Apply change","tool-apply-change"),item("List branches","tool-list-branches"),item("Rollback branch","tool-rollback-branch"),item("Rollback to count","tool-rollback-branch-to-count"),item("Discard branch","tool-discard-branch"),item("Branch diff","tool-branch-diff"),item("Branch verdict","tool-branch-verdict"),item("Compare branches","tool-compare-branches"),item("Plan verdict","tool-plan-verdict"),item("Branch hand-back","tool-branch-handback"),item("In-use evidence","tool-in-use-evidence")]},
  {label:"CLI",items:[item("CLI reference","cli")]},
  {label:"Self-hosting",items:[item("Self-hosting","self-host"),item("Configuration","configuration")]},
  {label:"Reference",items:[item("Troubleshooting","troubleshooting"),item("Glossary","glossary"),item("FAQ","faq")]},
];
export const searchEntries = [
  {title:"Overview",description:"Give your agent a branch of your cloud.",href:"/",group:"Getting started",search:"home overview introduction emfirge"},
  {title:"Connect your agent",description:"Install Emfirge in Claude, Cursor, Codex, or another MCP client.",href:"/connect",group:"Getting started",search:"install connect setup claude cursor codex mcp"},
  ...documents.flatMap(doc => [
    {title:doc.title,description:doc.description,href:`/docs/${doc.slug}`,group:doc.group,search:`${doc.title} ${doc.description}`},
    ...doc.sections.map(s => ({title:s.title,description:s.paragraphs?.[0] ?? doc.description,href:`/docs/${doc.slug}#${s.id}`,group:doc.title,search:[s.title,...s.paragraphs ?? [],s.code,s.note,...s.table?.rows.flat() ?? []].join(" ").replaceAll("{soon}","coming soon ")})),
  ]),
];
