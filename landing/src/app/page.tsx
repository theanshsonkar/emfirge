import { Faq } from "@/components/Faq";
import { FounderNote } from "@/components/FounderNote";
import { Footer } from "@/components/Footer";
import { Header } from "@/components/Header";
import { Hero } from "@/components/Hero";
import { LabDefs } from "@/components/LabDefs";
import { LabProvider } from "@/components/LabProvider";
import { LiveBar } from "@/components/LiveBar";
import { Pricing } from "@/components/Pricing";
import { Questions } from "@/components/Questions";
import { Transcript } from "@/components/Transcript";
import { NAV } from "@/content";

export default function Page() {
  return (
    <LabProvider>
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-12 focus:z-[60] focus:rounded-md focus:bg-white focus:px-3 focus:py-2"
      >
        {NAV.skip}
      </a>
      <LabDefs />
      <LiveBar />
      <Header />
      <main id="main">
        <Hero />
        <Transcript />
        <Questions />
        <FounderNote />
        <Pricing />
        <Faq />
      </main>
      <Footer />
    </LabProvider>
  );
}
