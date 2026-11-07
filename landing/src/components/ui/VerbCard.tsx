import type { Verb } from "@/content";
import { Card } from "./Card";

export function VerbCard({ verb }: { verb: Verb }) {
  return (
    <Card className="flex h-full min-w-0 flex-col p-6">
      <h3 className="font-mono text-xl font-medium text-forge">{verb.name}</h3>
      <p className="mt-3 flex-1 leading-relaxed text-paper">{verb.line}</p>
      <code className="mt-5 block overflow-x-auto whitespace-nowrap rounded-lg bg-ink px-3 py-2.5 font-mono text-[12.5px] text-muted">
        {verb.example}
      </code>
    </Card>
  );
}
