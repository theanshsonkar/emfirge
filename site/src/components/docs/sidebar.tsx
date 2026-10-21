"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { ArrowUpRight, BookOpen, ChevronRight, Search } from "lucide-react";
import { docsNav } from "./nav";

type NavItem = { label: string; href: string };
type NavGroup = { label: string; items: NavItem[]; collapsible?: boolean };

function NavLinks({items,pathname,onNavigate}:{items:NavItem[];pathname:string;onNavigate?:()=>void}) {
  return <>{items.map(item => { const active=pathname===(item.href==="/"?"/":item.href); return <li key={item.href}><Link href={item.href} onClick={onNavigate} aria-current={active ? "page" : undefined} className={active ? "active" : ""}>{item.label}</Link></li>; })}</>;
}

// A collapsible group always shows its first item (the overview page) and folds the rest.
function CollapsibleGroup({group,pathname,onNavigate}:{group:NavGroup;pathname:string;onNavigate?:()=>void}) {
  const [first,...rest]=group.items;
  const containsActive=rest.some(item=>item.href===pathname);
  const [open,setOpen]=useState(containsActive);
  useEffect(()=>{ if(containsActive) setOpen(true); },[containsActive]);
  const listId=`nav-${group.label.toLowerCase().replace(/\s+/g,"-")}`;
  return <div className="nav-group nav-group-collapsible"><button type="button" className="nav-group-toggle" aria-expanded={open} aria-controls={listId} onClick={()=>setOpen(v=>!v)}><span>{group.label}</span><span className="nav-group-count">{rest.length}</span><ChevronRight size={14} className="nav-group-chevron"/></button><ul><NavLinks items={[first]} pathname={pathname} onNavigate={onNavigate}/></ul><ul id={listId} hidden={!open}><NavLinks items={rest} pathname={pathname} onNavigate={onNavigate}/></ul></div>;
}

export function DocsSidebar({onSearch,onNavigate}:{onSearch:()=>void;onNavigate?:()=>void}) {
  const pathname=usePathname();
  return <div className="sidebar-inner"><button className="sidebar-search" onClick={onSearch}><Search size={15}/><span>Search docs</span><kbd>⌘ K</kbd></button><nav aria-label="Documentation">{(docsNav as NavGroup[]).map(group => group.collapsible ? <CollapsibleGroup key={group.label} group={group} pathname={pathname} onNavigate={onNavigate}/> : <div className="nav-group" key={group.label}><p>{group.label}</p><ul><NavLinks items={group.items} pathname={pathname} onNavigate={onNavigate}/></ul></div>)}</nav><div className="sidebar-bottom"><BookOpen size={16}/><div><strong>Built for your agent.</strong><span>Grounded in your cloud.</span></div><Link href="/connect" onClick={onNavigate} aria-label="Connect your agent"><ArrowUpRight size={17}/></Link></div></div>;
}
