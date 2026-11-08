import { Shell } from "@/components/Shell";
import { ON_THIS_PAGE } from "@/content/site";
import { Hero } from "@/components/Hero";
import { Prose } from "@/components/Prose";
import { TodoList } from "@/components/Todo";
import { Cta, Figure, Footer, Production, Runs, Trust, What, Writing } from "@/components/Sections";

export default function Page() {
  return (
    <Shell toc={ON_THIS_PAGE} mdUrl="/index.md">
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
      <TodoList page="" />
      <Footer />
    </Shell>
  );
}
