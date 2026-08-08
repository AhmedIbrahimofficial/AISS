import { createFileRoute } from "@tanstack/react-router";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

const m = MODULES["cloud-security"]!;

export const Route = createFileRoute("/cloud-security")({
  head: () => ({
    meta: [
      { title: "Cloud Security — AISS Security Operations" },
      { name: "description", content: "CSPM, workload protection and control-plane threat detection" },
      { property: "og:title", content: "Cloud Security — AISS" },
      { property: "og:description", content: "CSPM, workload protection and control-plane threat detection" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <ModulePage m={m} />,
});
