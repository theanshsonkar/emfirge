import type { Metadata } from "next";
import { Geist, Geist_Mono, Space_Grotesk } from "next/font/google";
import { ThemeProvider } from "@/components/theme-provider";
import { ThemeSync } from "@/components/theme-sync";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
});

// Display face for headings / wordmark, editorial-technical per brand brief (§6).
const spaceGrotesk = Space_Grotesk({
  variable: "--font-display",
  subsets: ["latin"],
  weight: ["500", "600", "700"],
});

export const metadata: Metadata = {
  metadataBase: new URL("https://emfirge.cloud"),
  title: "Emfirge: Fork your cloud. Prove the change. Then apply.",
  description:
    "A read-only engine that clones your AWS graph, applies a proposed change, re-runs 58 deterministic rules, and shows the risk delta before you touch prod.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning className={`${geistSans.variable} ${geistMono.variable} ${spaceGrotesk.variable} h-full`}>
      <body className="min-h-full font-sans antialiased">
        {/* Before first paint: opt into reveal animations only when the user
            hasn't asked for reduced motion. No-JS / reduced-motion users get
            fully-visible content (see .gsap-anim rules in globals.css). */}
        <script
          dangerouslySetInnerHTML={{
            __html:
              "(function(){try{if(!matchMedia('(prefers-reduced-motion: reduce)').matches){document.documentElement.classList.add('gsap-anim')}}catch(e){}})()",
          }}
        />
        <ThemeProvider
          attribute="class"
          defaultTheme="dark"
          enableSystem
          disableTransitionOnChange
        >
          <ThemeSync />
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}
