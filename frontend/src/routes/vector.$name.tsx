import { createFileRoute } from "@tanstack/react-router";
import { DetailPage } from "@/components/soc/DetailPage";

export const Route = createFileRoute("/vector/$name")({
  head: () => ({
    meta: [
      { title: "Attack Vector Analytics — AISS Security Operations" },
      { name: "description", content: "Complete statistics for the selected attack vector: volume, payloads, targets and blocks." },
      { property: "og:title", content: "Attack Vector Analytics — AISS" },
      { property: "og:description", content: "Complete statistics for the selected attack vector: volume, payloads, targets and blocks." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Page,
});

function Page() {
  const params = Route.useParams();
  return <DetailPage kind="vector" id={params.name} />;
}
