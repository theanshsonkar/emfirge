"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { NAV } from "@/lib/nav";

export function Sidebar() {
  const pathname = usePathname();
  return (
    <nav className="space-y-7">
      {NAV.map((section) => (
        <div key={section.label}>
          <div className="tag mb-2 px-3">{section.label}</div>
          <ul className="border-l border-border-soft">
            {section.items.map((item) => {
              const active = pathname === item.href;
              return (
                <li key={item.href} className="-ml-px">
                  <Link
                    href={item.href}
                    aria-current={active ? "page" : undefined}
                    className={`relative flex items-center rounded-md py-1.5 pl-4 pr-2 text-[13px] transition-colors ${
                      active
                        ? "bg-accent font-medium text-foreground"
                        : "text-muted-foreground hover:bg-accent/50 hover:text-foreground"
                    } ${item.mono ? "font-mono text-[12px]" : ""}`}
                  >
                    <span
                      className={`absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full transition-colors ${
                        active ? "bg-foreground" : "bg-transparent"
                      }`}
                    />
                    {item.title}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}
