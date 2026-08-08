import { createFileRoute } from "@tanstack/react-router";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

const m = MODULES["identity-protection"]!;

export const Route = createFileRoute("/identity-protection")({
  head: () => ({
    meta: [
      { title: "Identity Protection — AISS Security Operations" },
      { name: "description", content: "Account risk, impossible travel, token theft and privilege abuse detection" },
      { property: "og:title", content: "Identity Protection — AISS" },
      { property: "og:description", content: "Account risk, impossible travel, token theft and privilege abuse detection" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <ModulePage m={m} />,
});
