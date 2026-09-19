"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ArrowUpRight, BookOpen, Search } from "lucide-react";
import { docsNav } from "./nav";

export function DocsSidebar({onSearch,onNavigate}:{onSearch:()=>void;onNavigate?:()=>void}) {
  const pathname=usePathname();
  return <div className="sidebar-inner"><button className="sidebar-search" onClick={onSearch}><Search size={15}/><span>Search docs</span><kbd>⌘ K</kbd></button><nav aria-label="Documentation">{docsNav.map(group => <div className="nav-group" key={group.label}><p>{group.label}</p><ul>{group.items.map(item => <li key={item.href}><Link href={item.href} onClick={onNavigate} aria-current={pathname===item.href ? "page" : undefined} className={pathname===item.href ? "active" : ""}>{item.label}</Link></li>)}</ul></div>)}</nav><div className="sidebar-bottom"><BookOpen size={16}/><div><strong>Built for your agent.</strong><span>Grounded in your cloud.</span></div><Link href="/connect" onClick={onNavigate} aria-label="Connect your agent"><ArrowUpRight size={17}/></Link></div></div>;
}
