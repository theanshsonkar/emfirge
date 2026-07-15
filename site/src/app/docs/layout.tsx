import { Topbar } from "@/components/docs/topbar";
import { Sidebar } from "@/components/docs/sidebar";
import { Toc } from "@/components/docs/toc";
import { MobileToc } from "@/components/docs/mobile-toc";
import { Breadcrumbs } from "@/components/docs/breadcrumbs";
import { PageFooter } from "@/components/docs/page-footer";
import { RouteProgress } from "@/components/docs/route-progress";
import { ScrollToTop } from "@/components/docs/scroll-to-top";

export default function DocsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-background">
      <ScrollToTop />
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-3 focus:z-[100] focus:rounded-md focus:border focus:border-border focus:bg-background focus:px-3 focus:py-2 focus:text-[13px] focus:font-medium focus:text-foreground focus:shadow-[var(--elev)]"
      >
        Skip to content
      </a>
      <RouteProgress />
      <Topbar />
      <div className="mx-auto flex max-w-[1600px]">
        {/* left nav */}
        <aside className="rail-scroll sticky top-14 hidden h-[calc(100vh-3.5rem)] w-[17rem] shrink-0 overflow-y-auto border-r border-border px-3 py-7 lg:block">
          <Sidebar />
        </aside>

        {/* content */}
        <main id="main-content" className="relative min-w-0 flex-1 border-border px-6 py-12 md:px-14 lg:px-16 xl:border-r">
          <article className="mx-auto max-w-[46rem]">
            <Breadcrumbs />
            <MobileToc />
            {children}
            <PageFooter />
          </article>
        </main>

        {/* right toc */}
        <aside className="rail-scroll sticky top-14 hidden h-[calc(100vh-3.5rem)] w-60 shrink-0 overflow-y-auto px-7 py-12 xl:block">
          <Toc />
        </aside>
      </div>
    </div>
  );
}
