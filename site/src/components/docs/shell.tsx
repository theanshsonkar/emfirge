"use client";
import { useCallback,useEffect,useRef,useState,type ReactNode } from "react";
import { usePathname } from "next/navigation";
import { X } from "lucide-react";
import { DocsTopBar } from "./top-bar";
import { DocsSidebar } from "./sidebar";
import { DocsSearch } from "./search";
import { OnThisPage } from "./on-this-page";
export function DocsShell({children,connect=false}:{children:ReactNode;connect?:boolean}){
 const pathname=usePathname();const home=pathname==="/docs";
 const [search,setSearch]=useState(false);const [mobile,setMobile]=useState(false);const [theme,setTheme]=useState<"dark"|"light">("dark");const drawer=useRef<HTMLDialogElement>(null);
 const closeSearch=useCallback(()=>setSearch(false),[]);
 useEffect(()=>{try{const saved=localStorage.getItem("emfirge-docs-theme");if(saved==="light"||saved==="dark")setTheme(saved);}catch{}},[]);
 useEffect(()=>{function key(e:KeyboardEvent){if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==="k"){e.preventDefault();setMobile(false);setSearch(value=>!value);}}window.addEventListener("keydown",key);return()=>window.removeEventListener("keydown",key);},[]);
 useEffect(()=>{setMobile(false);},[pathname]);
 useEffect(()=>{if(mobile)drawer.current?.showModal();else drawer.current?.close();},[mobile]);
 useEffect(()=>{if(!search&&!mobile)return;const previous=document.body.style.overflow;document.body.style.overflow="hidden";return()=>{document.body.style.overflow=previous;};},[search,mobile]);
 function toggleTheme(){setTheme(current=>{const next=current==="dark"?"light":"dark";try{localStorage.setItem("emfirge-docs-theme",next);}catch{}return next;});}
 return <div className="docs-shell" data-theme={theme}><a className="skip-link" href="#main-content">Skip to content</a><DocsTopBar onSearch={()=>setSearch(true)} onMenu={()=>setMobile(v=>!v)} mobileOpen={mobile} theme={theme} onTheme={toggleTheme}/>{connect?<main id="main-content" tabIndex={-1} className="connect-main">{children}</main>:<div className={`docs-body ${home?"is-home":""}`}><aside className="docs-sidebar"><DocsSidebar onSearch={()=>setSearch(true)}/></aside><main id="main-content" tabIndex={-1} className="docs-main">{children}</main>{!home&&<OnThisPage/>}</div>}<dialog id="mobile-docs-nav" ref={drawer} className="mobile-docs-dialog" aria-label="Documentation navigation" onCancel={()=>setMobile(false)} onClick={e=>{if(e.target===e.currentTarget)setMobile(false);}}><div className="drawer-title"><strong>Documentation</strong><button className="icon-button" onClick={()=>setMobile(false)} aria-label="Close navigation"><X size={20}/></button></div><DocsSidebar onSearch={()=>{setMobile(false);setSearch(true);}} onNavigate={()=>setMobile(false)}/></dialog><DocsSearch open={search} onClose={closeSearch}/></div>;
}
