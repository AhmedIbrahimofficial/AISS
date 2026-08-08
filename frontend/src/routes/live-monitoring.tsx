import { createFileRoute } from "@tanstack/react-router";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

const m = MODULES["live-monitoring"]!;

export const Route = createFileRoute("/live-monitoring")({
  head: () => ({
    meta: [
      { title: "Live Monitoring — AISS Security Operations" },
      { name: "description", content: "Streaming sensor telemetry, session activity and real-time anomaly scoring" },
      { property: "og:title", content: "Live Monitoring — AISS" },
      { property: "og:description", content: "Streaming sensor telemetry, session activity and real-time anomaly scoring" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <ModulePage m={m} />,
});
