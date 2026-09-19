import type { Metadata } from "next";
import { DocsHome } from "@/components/docs/home";
export const metadata:Metadata={title:"Emfirge documentation — A cloud harness for AI agents",description:"Connect your agent, create a branch of your cloud, and understand infrastructure changes before they become real."};
export default function DocsPage(){return <DocsHome/>;}
