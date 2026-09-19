"use client";
import { useEffect,useState } from "react";
import { usePathname } from "next/navigation";
import { ArrowUpRight } from "lucide-react";
import { SOURCE_URL } from "./content";
export function OnThisPage(){
 const pathname=usePathname();
 const [headings,setHeadings]=useState<{id:string;text:string}[]>([]);
 const [active,setActive]=useState("");
 useEffect(()=>{
   const nodes=Array.from(document.querySelectorAll<HTMLElement>(".doc-article h2[id]"));
   setHeadings(nodes.map(node=>({id:node.id,text:node.textContent??""})));setActive(nodes[0]?.id??"");
   function update(){ let id=nodes[0]?.id??""; for(const node of nodes) if(node.getBoundingClientRect().top<=170) id=node.id;setActive(id); }
   update();window.addEventListener("scroll",update,{passive:true});return()=>window.removeEventListener("scroll",update);
 },[pathname]);
 if(!headings.length)return null;
 return <aside className="docs-toc"><div><p>On this page</p><nav aria-label="On this page">{headings.map(h=><a href={`#${h.id}`} key={h.id} aria-current={active===h.id?"location":undefined}>{h.text.replace("emfirge_","").replace(/#$/, "")}</a>)}</nav><a className="toc-help" href={`${SOURCE_URL}/issues`} target="_blank" rel="noreferrer">Suggest an improvement <ArrowUpRight size={13}/></a></div></aside>;
}
