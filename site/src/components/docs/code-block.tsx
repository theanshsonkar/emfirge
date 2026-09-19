"use client";
import { Check, Copy } from "lucide-react";
import { useEffect, useRef, useState } from "react";

function highlight(line: string) {
  return line.split(/("[^"\n]*"|\/\/.*$|#.*$|\b(?:false|true|emfirge_\w+|npx)\b)/g).map((part, index) =>
    <span key={index} className={part.startsWith('"') ? "code-string" : /^(\/\/|#)/.test(part) ? "code-comment" : /^(false|true|emfirge_|npx)/.test(part) ? "code-keyword" : undefined}>{part}</span>);
}
export function CopyButton({text,label="Copy code"}:{text:string;label?:string}) {
  const [state,setState] = useState<"idle"|"copied"|"failed">("idle");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => {if(timer.current) clearTimeout(timer.current);},[]);
  async function copy() {
    try { await navigator.clipboard.writeText(text); setState("copied"); }
    catch {setState("failed");}
    if(timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setState("idle"),2500);
  }
  return <button className="copy-button" type="button" onClick={copy} aria-label={state === "copied" ? "Copied" : label} title={label}>{state === "copied" ? <Check size={15}/> : <Copy size={15}/>}<span aria-live="polite">{state === "copied" ? "Copied" : state === "failed" ? "Select to copy" : ""}</span></button>;
}
export function CodeBlock({code,language="MCP tool call",numbered=false,tabs}:{code?:string;language?:string;numbered?:boolean;tabs?:{label:string;code:string}[]}) {
  const displayCode = code ?? tabs?.[0]?.code ?? "";
  const displayLanguage = language ?? tabs?.[0]?.label ?? "MCP tool call";
  return <div className="docs-code"><div className="code-header"><span>{displayLanguage}</span><CopyButton text={displayCode}/></div><pre tabIndex={0} aria-label={displayLanguage}><code>{displayCode.split("\n").map((line,i) => <span className="code-line" key={i}>{numbered && <span className="line-number" aria-hidden="true">{i+1}</span>}<span>{highlight(line)}{line === "" ? " " : ""}</span>{"\n"}</span>)}</code></pre></div>;
}
