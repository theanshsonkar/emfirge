import { cn } from "@/lib/cn";

export function Container({ className, ...props }: React.ComponentProps<"div">) {
  return <div className={cn("mx-auto w-full max-w-[1200px] px-4 md:px-6", className)} {...props} />;
}
