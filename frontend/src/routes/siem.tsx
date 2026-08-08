import { createFileRoute } from "@tanstack/react-router";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

const m = MODULES["siem"]!;

export const Route = createFileRoute("/siem")({
  head: () => ({
    meta: [
      { title: "SIEM — AISS Security Operations" },
      { name: "description", content: "Correlation engine, saved searches and detection-as-code pipeline" },
      { property: "og:title", content: "SIEM — AISS" },
      { property: "og:description", content: "Correlation engine, saved searches and detection-as-code pipeline" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <ModulePage m={m} />,
});
