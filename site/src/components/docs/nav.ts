import { documents } from "./content";

const item = (label: string, href: string) => ({ label, href: `/docs/${href}` });
export const docsNav = [
  {label:"Getting started",items:[{label:"Overview",href:"/docs"},item("Developer quickstart","quickstart"),item("How the fork works","how-it-works")]},
  {label:"Concepts",items:[item("Key concepts","concepts"),item("Create and compare branches","branches"),item("Apply changes","changes"),item("Read diffs and verdicts","diffs"),item("Lenses and coverage","lenses"),item("The infrastructure graph","graph")]},
  {label:"Safety & privacy",items:[item("Safety and model limits","safety"),item("Privacy modes","privacy"),item("Security model","security")]},
  {label:"MCP tools",items:[item("MCP tool reference","mcp"),item("Scan","tool-scan"),item("Get findings","tool-get-findings"),item("Attack paths","tool-attack-paths"),item("Create branch","tool-create-branch"),item("Setup help","tool-setup-help"),item("Branch verdict","tool-branch-verdict"),item("Branch diff","tool-branch-diff"),item("List branches","tool-list-branches"),item("Rollback branch","tool-rollback-branch"),item("Verify fix","tool-verify-fix"),item("Apply change","tool-apply-change"),item("Compare branches","tool-compare-branches"),item("Check compliance","tool-check-compliance"),item("Discard branch","tool-discard-branch"),item("Simulate breach","tool-simulate-breach")]},
  {label:"CLI",items:[item("CLI reference","cli")]},
  {label:"Self-hosting",items:[item("Self-hosting","self-host"),item("Configuration","configuration")]},
  {label:"Reference",items:[item("Troubleshooting","troubleshooting"),item("Glossary","glossary"),item("FAQ","faq")]},
];
export const searchEntries = [
  {title:"Overview",description:"Give your agent a branch of your cloud.",href:"/docs",group:"Getting started",search:"home overview introduction emfirge"},
  {title:"Connect your agent",description:"Install Emfirge in Claude, Cursor, Codex, or another MCP client.",href:"/connect",group:"Getting started",search:"install connect setup claude cursor codex mcp"},
  ...documents.flatMap(doc => [
    {title:doc.title,description:doc.description,href:`/docs/${doc.slug}`,group:doc.group,search:`${doc.title} ${doc.description}`},
    ...doc.sections.map(s => ({title:s.title,description:s.paragraphs?.[0] ?? doc.description,href:`/docs/${doc.slug}#${s.id}`,group:doc.title,search:[s.title,...s.paragraphs ?? [],s.code,s.note,...s.table?.rows.flat() ?? []].join(" ")})),
  ]),
];
