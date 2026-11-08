import { Shell } from "@/components/Shell";
import { Hero } from "@/components/Hero";
import { Prose } from "@/components/Prose";
import { Cta, Figure, Footer, Production, Runs, Trust, What, Writing } from "@/components/Sections";

export default function Page() {
  return (
    <Shell>
      <span id="top" />
      <Hero />
      <Prose />
      <Figure />
      <What />
      <Production />
      <Runs />
      <Trust />
      <Cta />
      <Writing />
      <Footer />
    </Shell>
  );
}
