import { createFileRoute } from "@tanstack/react-router";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

const m = MODULES["sandbox"]!;

export const Route = createFileRoute("/sandbox")({
  head: () => ({
    meta: [
      { title: "Sandbox — AISS Security Operations" },
      { name: "description", content: "Detonation environments, behavioural traces and network capture" },
      { property: "og:title", content: "Sandbox — AISS" },
      { property: "og:description", content: "Detonation environments, behavioural traces and network capture" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <ModulePage m={m} />,
});
