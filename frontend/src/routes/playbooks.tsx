import { createFileRoute } from "@tanstack/react-router";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

const m = MODULES["playbooks"]!;

export const Route = createFileRoute("/playbooks")({
  head: () => ({
    meta: [
      { title: "Playbooks — AISS Security Operations" },
      { name: "description", content: "Response automation library with approval gates and success metrics" },
      { property: "og:title", content: "Playbooks — AISS" },
      { property: "og:description", content: "Response automation library with approval gates and success metrics" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <ModulePage m={m} />,
});
