import { createFileRoute } from "@tanstack/react-router";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

const m = MODULES["logs"]!;

export const Route = createFileRoute("/logs")({
  head: () => ({
    meta: [
      { title: "Log Explorer — AISS Security Operations" },
      { name: "description", content: "Raw event search across endpoint, cloud, identity and network sources" },
      { property: "og:title", content: "Log Explorer — AISS" },
      { property: "og:description", content: "Raw event search across endpoint, cloud, identity and network sources" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <ModulePage m={m} />,
});
