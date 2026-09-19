import { GeistMono } from "geist/font/mono";
import { GeistSans } from "geist/font/sans";
import { DocsShell } from "@/components/docs/shell";

export default function DocsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className={`${GeistSans.variable} ${GeistMono.variable}`}>
      <DocsShell>{children}</DocsShell>
    </div>
  );
}
