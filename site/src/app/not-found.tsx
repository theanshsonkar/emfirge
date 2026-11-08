import { Shell } from "@/components/Shell";
import { Footer } from "@/components/Sections";

export const metadata = { title: "Page not found · emfirge" };

export default function NotFound() {
  return (
    <Shell toc={[{ id: "top", label: "Page not found" }]} mdUrl="/index.md">
      <span id="top" />
      <header className="dp-head">
        <div className="label">Error 404</div>
        <h1 className="dp-h1" style={{ marginTop: 14 }}>This page took a branch<br />that does not exist.</h1>
        <p className="dp-lead">
          The page you asked for is not here. Go to the <a className="uline" href="/">home page</a>, set up emfirge with the{" "}
          <a className="uline" href="/quickstart/">Set up</a> page, or read the <a className="uline" href="/cli/">CLI reference</a>.
        </p>
      </header>
      <Footer />
    </Shell>
  );
}
