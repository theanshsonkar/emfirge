"use client";

import { motion, useReducedMotion } from "motion/react";
import { cn } from "@/lib/cn";

/** Raised surface with an optional hover lift. */
export function Card({
  className,
  lift = true,
  children,
}: {
  className?: string;
  lift?: boolean;
  children: React.ReactNode;
}) {
  const reduce = useReducedMotion();
  return (
    <motion.div
      whileHover={lift && !reduce ? { y: -4 } : undefined}
      transition={{ type: "spring", stiffness: 400, damping: 28 }}
      className={cn(
        "rounded-[14px] border border-line bg-surface transition-colors",
        lift && "hover:border-muted/60",
        className,
      )}
    >
      {children}
    </motion.div>
  );
}
