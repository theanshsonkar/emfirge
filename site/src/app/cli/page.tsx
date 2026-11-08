import type { Metadata } from "next";
import { DocPage } from "@/components/DocPage";
import { cli as page } from "@/content/cli";

export const metadata: Metadata = {
  title: `${page.title} · emfirge`,
  description: page.description,
  alternates: { canonical: page.href, types: { "text/markdown": `/${page.slug}.md` } },
};

export default function Page() {
  return <DocPage page={page} />;
}
