import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { documents } from "@/components/docs/content";
import { DocArticle } from "@/components/docs/article";
export function generateStaticParams(){return documents.map(doc=>({slug:doc.slug}));}
export async function generateMetadata({params}:{params:Promise<{slug:string}>}):Promise<Metadata>{const {slug}=await params;const doc=documents.find(d=>d.slug===slug);return {title:doc?`${doc.title} — Emfirge Docs`:"Page not found — Emfirge",description:doc?.description};}
export default async function DocumentationPage({params}:{params:Promise<{slug:string}>}){const {slug}=await params;const doc=documents.find(d=>d.slug===slug);if(!doc)notFound();return <DocArticle doc={doc}/>;}
