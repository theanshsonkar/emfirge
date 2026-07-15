import { createHighlighter, type Highlighter } from "shiki";
import { CodeBlockClient } from "./code-block-client";

export type CodeTab = { label: string; code: string };

// Shared highlighter (built once per build). Always-dark rail → one dark theme.
let hlPromise: Promise<Highlighter> | null = null;
function getHighlighter() {
  if (!hlPromise) {
    hlPromise = createHighlighter({
      themes: ["vitesse-dark"],
      langs: ["json", "bash"],
    });
  }
  return hlPromise;
}

function escapeHtml(s: string) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function detectLang(label: string, code: string): "json" | "bash" | "text" {
  const l = label.toLowerCase();
  if (l.includes("json") || l.includes("argument") || l.includes("response") || l.includes("result") || l === "mcp.json") return "json";
  if (l.includes("terminal")) return "bash";
  const t = code.trimStart();
  if (t.startsWith("{") || t.startsWith("[")) return "json";
  if (/^(npx|\$|#|sudo|cd |docker|export )/m.test(t)) return "bash";
  return "text";
}

export async function CodeBlock({
  tabs,
  numbered = false,
  footer,
  className = "",
}: {
  tabs: CodeTab[];
  numbered?: boolean;
  footer?: React.ReactNode;
  className?: string;
}) {
  const hl = await getHighlighter();
  const rendered = tabs.map((t) => {
    const code = t.code.replace(/\n$/, "");
    const lang = detectLang(t.label, code);
    const html =
      lang === "text"
        ? `<pre class="shiki"><code>${code
            .split("\n")
            .map((line) => `<span class="line">${escapeHtml(line) || "&nbsp;"}</span>`)
            .join("\n")}</code></pre>`
        : hl.codeToHtml(code, { lang, theme: "vitesse-dark" });
    return { label: t.label, code, html };
  });

  return <CodeBlockClient tabs={rendered} numbered={numbered} footer={footer} className={className} />;
}
