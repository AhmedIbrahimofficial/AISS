import { createFileRoute } from "@tanstack/react-router";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

const m = MODULES["network-monitor"]!;

export const Route = createFileRoute("/network-monitor")({
  head: () => ({
    meta: [
      { title: "Network Monitor — AISS Security Operations" },
      { name: "description", content: "Flow analytics, east-west visibility and perimeter enforcement" },
      { property: "og:title", content: "Network Monitor — AISS" },
      { property: "og:description", content: "Flow analytics, east-west visibility and perimeter enforcement" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <ModulePage m={m} />,
});
