import { createFileRoute } from "@tanstack/react-router";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

const m = MODULES["threat-intelligence"]!;

export const Route = createFileRoute("/threat-intelligence")({
  head: () => ({
    meta: [
      { title: "Threat Intelligence — AISS Security Operations" },
      { name: "description", content: "IOC enrichment, actor tracking and feed correlation across 14 providers" },
      { property: "og:title", content: "Threat Intelligence — AISS" },
      { property: "og:description", content: "IOC enrichment, actor tracking and feed correlation across 14 providers" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <ModulePage m={m} />,
});
