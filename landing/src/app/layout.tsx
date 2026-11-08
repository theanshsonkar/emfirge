import type { Metadata, Viewport } from "next";
import { Archivo, IBM_Plex_Mono } from "next/font/google";
import { SITE } from "@/content";
import "./globals.css";

// Archivo's width axis carries the display voice (wdth 125, 800).
const sans = Archivo({
  subsets: ["latin"],
  axes: ["wdth"],
  variable: "--font-archivo",
  display: "swap",
});
const mono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-plex",
  display: "swap",
});

export const metadata: Metadata = {
  title: SITE.title,
  description: SITE.description,
};

export const viewport: Viewport = { themeColor: "#000000" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body>
        <noscript>
          {/* Without JS the bench is a finished example: test 001, switches disabled. */}
          <style>{`[data-js]{display:none!important}[data-sw="1"] .sw-cover{transform:rotateX(-112deg)}[data-sw="1"] .sw-lever{transform:translateY(-10px)}`}</style>
        </noscript>
        {children}
      </body>
    </html>
  );
}
