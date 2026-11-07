import { Announcement } from "@/components/Announcement";
import { Footer } from "@/components/Footer";
import { GetStarted } from "@/components/GetStarted";
import { Hero } from "@/components/Hero";
import { Nav } from "@/components/Nav";
import { Numbers } from "@/components/Numbers";
import { Principles } from "@/components/Principles";
import { SplitPanel } from "@/components/SplitPanel";
import { World } from "@/components/World";
import { WorksWith } from "@/components/WorksWith";
import { NAV } from "@/content";

export default function Page() {
  return (
    <>
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-white focus:px-3 focus:py-2 focus:text-ink"
      >
        {NAV.skip}
      </a>
      <Announcement />
      <Nav />
      <main id="main">
        <Hero />
        <WorksWith />
        <SplitPanel />
        <World />
        <Principles />
        <Numbers />
        <GetStarted />
      </main>
      <Footer />
    </>
  );
}
