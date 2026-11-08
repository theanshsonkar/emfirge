import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { SITE } from "@/content";
import "./globals.css";

const sans = Geist({ subsets: ["latin"], variable: "--font-geist", display: "swap" });
const mono = Geist_Mono({ subsets: ["latin"], variable: "--font-geist-mono", display: "swap", weight: ["400", "500"] });

export const metadata: Metadata = {
  metadataBase: new URL("https://emfirge.cloud"),
  title: SITE.title,
  description: SITE.description,
  alternates: { types: { "text/markdown": "/index.md" } },
  openGraph: { type: "website", url: "/", siteName: "Emfirge", title: SITE.title, description: SITE.description },
  twitter: { card: "summary", title: SITE.title, description: SITE.description },
};
export const viewport: Viewport = { themeColor: "#ffffff" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable} no-js`}>
      <head>
        <script dangerouslySetInnerHTML={{ __html: "document.documentElement.classList.remove('no-js')" }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
