import { createFileRoute } from "@tanstack/react-router";
import { DetailPage } from "@/components/soc/DetailPage";

export const Route = createFileRoute("/investigate/$type/$id")({
  head: () => ({
    meta: [
      { title: "Investigation — AISS Security Operations" },
      { name: "description", content: "Full investigation view with evidence, IOCs, MITRE mapping and AI remediation guidance." },
      { property: "og:title", content: "Investigation — AISS" },
      { property: "og:description", content: "Full investigation view with evidence, IOCs, MITRE mapping and AI remediation guidance." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Page,
});

function Page() {
  const params = Route.useParams();
  return <DetailPage kind="entity" id={params.id} />;
}
