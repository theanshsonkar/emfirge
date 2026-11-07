import type { Metadata } from "next";
import { Instrument_Serif, Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const instrument = Instrument_Serif({
  weight: "400",
  style: ["normal", "italic"],
  subsets: ["latin"],
  variable: "--font-instrument",
  display: "swap",
});
const inter = Inter({ subsets: ["latin"], variable: "--font-inter", display: "swap" });
const jetbrains = JetBrains_Mono({ subsets: ["latin"], variable: "--font-jetbrains", display: "swap" });

export const metadata: Metadata = {
  title: "Emfirge: the harness for cloud agents",
  description:
    "Emfirge gives your coding agent a true model of your AWS, a branch to try changes on, and facts about what would break, before anything reaches production.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${instrument.variable} ${inter.variable} ${jetbrains.variable}`}>
      <body>
        {/* No JS: undo the initial hidden state used by scroll reveals and the FAQ animation. */}
        <noscript>
          <style>{`[data-reveal]{opacity:1!important;transform:none!important}details>[data-faq-body]{height:auto!important;opacity:1!important}`}</style>
        </noscript>
        {children}
        <div aria-hidden="true" className="grain" />
      </body>
    </html>
  );
}
