import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export function Panel({
  title,
  right,
  className,
  bodyClassName,
  children,
}: {
  title?: string;
  right?: ReactNode;
  className?: string;
  bodyClassName?: string;
  children: ReactNode;
}) {
  return (
    <section className={cn("panel flex flex-col p-4", className)}>
      {title && (
        <header className="mb-3 flex items-center justify-between gap-3">
          <h2 className="label-cap">{title}</h2>
          {right}
        </header>
      )}
      <div className={cn("flex min-h-0 flex-1 flex-col", bodyClassName)}>{children}</div>
    </section>
  );
}
