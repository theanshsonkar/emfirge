import { Nav } from "@/components/Nav";
import { Hero } from "@/components/Hero";
import { WorksWith } from "@/components/WorksWith";
import { Problem } from "@/components/Problem";
import { Comparison } from "@/components/Comparison";
import { Loop } from "@/components/Loop";
import { Verbs } from "@/components/Verbs";
import { DamageQuestions } from "@/components/DamageQuestions";
import { Facts } from "@/components/Facts";
import { EmfirgeMd } from "@/components/EmfirgeMd";
import { UseCases } from "@/components/UseCases";
import { Safety } from "@/components/Safety";
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
        <Problem />
        <Comparison />
        <Loop />
        <Verbs />
        <DamageQuestions />
        <Facts />
        <EmfirgeMd />
        <UseCases />
        <Safety />
        <GetStarted />
        <Faq />
        <FinalCta />
      </main>
    </>
  );
}
