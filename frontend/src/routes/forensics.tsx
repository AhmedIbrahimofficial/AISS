import { createFileRoute } from "@tanstack/react-router";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

const m = MODULES["forensics"]!;

export const Route = createFileRoute("/forensics")({
  head: () => ({
    meta: [
      { title: "Forensics — AISS Security Operations" },
      { name: "description", content: "Evidence acquisition, memory analysis and chain of custody" },
      { property: "og:title", content: "Forensics — AISS" },
      { property: "og:description", content: "Evidence acquisition, memory analysis and chain of custody" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <ModulePage m={m} />,
});
