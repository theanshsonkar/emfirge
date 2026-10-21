import type { Metadata } from "next";
import { GeistMono } from "geist/font/mono";
import { GeistSans } from "geist/font/sans";
import { ConnectAgent } from "@/components/docs/connect";
import { DocsShell } from "@/components/docs/shell";

export const metadata: Metadata = {
  title: "Connect your agent — Emfirge",
  description: "Install Emfirge in Claude, Cursor, Codex, Kiro, or another MCP client and give your agent a branch of your cloud.",
};

export default function ConnectPage() {
  return (
    <div className={`${GeistSans.variable} ${GeistMono.variable}`}>
      <DocsShell connect>
        <ConnectAgent />
      </DocsShell>
    </div>
  );
}
