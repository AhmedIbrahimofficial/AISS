import { createFileRoute } from "@tanstack/react-router";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

const m = MODULES["firewall"]!;

export const Route = createFileRoute("/firewall")({
  head: () => ({
    meta: [
      { title: "Firewall — AISS Security Operations" },
      { name: "description", content: "Policy enforcement, rule hit analytics and edge blocklist management" },
      { property: "og:title", content: "Firewall — AISS" },
      { property: "og:description", content: "Policy enforcement, rule hit analytics and edge blocklist management" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <ModulePage m={m} />,
});
