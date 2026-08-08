import { createFileRoute } from "@tanstack/react-router";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

const m = MODULES["license"]!;

export const Route = createFileRoute("/license")({
  head: () => ({
    meta: [
      { title: "License — AISS Security Operations" },
      { name: "description", content: "Entitlements, sensor consumption and contract utilisation" },
      { property: "og:title", content: "License — AISS" },
      { property: "og:description", content: "Entitlements, sensor consumption and contract utilisation" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <ModulePage m={m} />,
});
