import Link from "next/link";
export default function NotFound(){return <article className="doc-article"><div className="doc-eyebrow">404</div><h1>This page isn’t here.</h1><p className="doc-description">Search the documentation or return to the overview to find your way.</p><Link className="button-primary" href="/docs">Back to documentation</Link></article>;}
