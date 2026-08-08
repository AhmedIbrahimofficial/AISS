import { createFileRoute } from "@tanstack/react-router";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

const m = MODULES["ids-ips"]!;

export const Route = createFileRoute("/ids-ips")({
  head: () => ({
    meta: [
      { title: "IDS / IPS — AISS Security Operations" },
      { name: "description", content: "Signature and behavioural intrusion prevention across all inspection points" },
      { property: "og:title", content: "IDS / IPS — AISS" },
      { property: "og:description", content: "Signature and behavioural intrusion prevention across all inspection points" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <ModulePage m={m} />,
});
