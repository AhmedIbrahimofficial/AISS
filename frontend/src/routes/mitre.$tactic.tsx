import { createFileRoute } from "@tanstack/react-router";
import { DetailPage } from "@/components/soc/DetailPage";

export const Route = createFileRoute("/mitre/$tactic")({
  head: () => ({
    meta: [
      { title: "MITRE ATT&CK Technique — AISS Security Operations" },
      { name: "description", content: "Technique detail: detection rules, alerts, affected hosts, coverage and recommendations." },
      { property: "og:title", content: "MITRE ATT&CK Technique — AISS" },
      { property: "og:description", content: "Technique detail: detection rules, alerts, affected hosts, coverage and recommendations." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Page,
});

function Page() {
  const params = Route.useParams();
  return <DetailPage kind="mitre" id={params.tactic} />;
}
