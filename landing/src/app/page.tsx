import { Nav } from "@/components/Nav";
import { Hero } from "@/components/Hero";
import { WorksWith } from "@/components/WorksWith";
import { Harness } from "@/components/Harness";
import { HowItWorks } from "@/components/HowItWorks";
import { Questions } from "@/components/Questions";
import { GetStarted } from "@/components/GetStarted";
import { Faq } from "@/components/Faq";
import { FinalCta } from "@/components/FinalCta";

export default function Page() {
  return (
    <>
      <Nav />
      <main>
        <Hero />
        <WorksWith />
        <Harness />
        <HowItWorks />
        <Questions />
        <GetStarted />
        <Faq />
        <FinalCta />
      </main>
    </>
  );
}
