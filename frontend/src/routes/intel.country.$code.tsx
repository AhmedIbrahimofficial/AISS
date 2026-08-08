import { createFileRoute } from "@tanstack/react-router";
import { DetailPage } from "@/components/soc/DetailPage";

export const Route = createFileRoute("/intel/country/$code")({
  head: () => ({
    meta: [
      { title: "Country Threat Intelligence — AISS Security Operations" },
      { name: "description", content: "Attack volume, top IPs, ASNs, threat actors, malware families and campaign timelines." },
      { property: "og:title", content: "Country Threat Intelligence — AISS" },
      { property: "og:description", content: "Attack volume, top IPs, ASNs, threat actors, malware families and campaign timelines." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Page,
});

function Page() {
  const params = Route.useParams();
  return <DetailPage kind="country" id={params.code} />;
}
