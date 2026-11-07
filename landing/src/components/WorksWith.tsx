import { WORKS_WITH } from "@/content";
import { Frame } from "./Frame";

export function WorksWith() {
  return (
    <section aria-labelledby="works-with" className="border-b border-line bg-white">
      <Frame>
        <h2 id="works-with" className="px-4 pb-4 pt-8 text-sm font-normal text-ink-3 sm:px-6 lg:px-12">
          {WORKS_WITH.heading}
        </h2>
        <ul className="grid grid-cols-2 border-t border-line md:grid-cols-6">
          {WORKS_WITH.agents.map((a) => (
            <li
              key={a}
              className="flex h-24 items-center justify-center border-b border-line text-lg font-medium text-ink-3 odd:border-r max-md:last:border-b-0 md:border-b-0 md:border-r md:last:border-r-0 md:odd:border-r"
            >
              {a}
            </li>
          ))}
        </ul>
      </Frame>
    </section>
  );
}
