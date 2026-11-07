import { BranchWindow } from "@/components/BranchWindow";
import { Compare } from "@/components/Compare";
import { Faq } from "@/components/Faq";
import { FinalCta, Footer } from "@/components/FinalCta";
import { FounderNote } from "@/components/FounderNote";
import { ForkPattern } from "@/components/ForkPattern";
import { Hero } from "@/components/Hero";
import { HowItWorks } from "@/components/HowItWorks";
import { Nav } from "@/components/Nav";
import { Notifications } from "@/components/Notifications";
import { PricingCard } from "@/components/PricingCard";
import { Tweets } from "@/components/Tweets";
import { NAV } from "@/content";

export default function Page() {
  return (
    <div className="relative">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-[60] focus:rounded-lg focus:bg-white focus:px-3 focus:py-2 focus:text-ink"
      >
        {NAV.skip}
      </a>
      <ForkPattern />
      <Nav />
      <main id="main" className="relative">
        <Hero />
        <HowItWorks />
        <BranchWindow />
        <Notifications />
        <Compare />
        <Tweets />
        <FounderNote />
        <PricingCard />
        <Faq />
        <FinalCta />
      </main>
      <Footer />
    </div>
  );
}
