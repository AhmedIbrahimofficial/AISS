import { createFileRoute } from "@tanstack/react-router";
import { PageHeader } from "@/components/soc/AppShell";
import { Panel } from "@/components/soc/Panel";
import { Badge, DataTable, Metric } from "@/components/soc/ui";
import { ThreatChart } from "@/components/soc/ThreatChart";
import { Heatmap } from "@/components/soc/Heatmap";

export const Route = createFileRoute("/reports")({
  head: () => ({
    meta: [
      { title: "Reports & Analytics — AISS Security Console" },
      {
        name: "description",
        content:
          "Executive and operational security reporting: detection trends, MTTR, coverage and scheduled exports.",
      },
      { property: "og:title", content: "Reports & Analytics — AISS" },
      {
        property: "og:description",
        content: "Detection trends, response metrics and scheduled security report exports.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: ReportsPage,
});

function ReportsPage() {
  return (
    <div>
      <PageHeader
        title="Reports & Analytics"
        subtitle="Trends, benchmarks and scheduled exports for leadership and auditors"
      />

      <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Detections (30d)" value="41,206" tone="info" sub="+8% vs prior period" />
        <Metric label="Auto-Resolved" value="94.1%" tone="success" />
        <Metric label="Mean Time to Respond" value="4.2s" tone="success" sub="AI containment" />
        <Metric label="Analyst Hours Saved" value="612" sub="estimated, 30d" />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <ThreatChart />
        </div>
        <Heatmap />
      </div>

      <div className="mt-4">
        <Panel className="p-4" title="Scheduled Reports">
          <DataTable
            columns={["Report", "Audience", "Cadence", "Format", "Next Run", "Status"]}
            rows={[
              ["Executive Security Summary", "Board", "Monthly", "PDF", "Sep 1, 09:00", "Active"],
              ["SOC Operations Review", "Security team", "Weekly", "PDF", "Mon 07:00", "Active"],
              ["Vulnerability Posture", "IT Ops", "Weekly", "CSV", "Fri 18:00", "Active"],
              ["Regulator Evidence Pack", "Compliance", "Quarterly", "ZIP", "Oct 1, 08:00", "Draft"],
              ["Threat Intel Digest", "All analysts", "Daily", "Email", "Tomorrow 06:00", "Active"],
            ].map((r) => [
              r[0],
              <span className="text-muted-foreground">{r[1]}</span>,
              r[2],
              <span className="font-mono text-xs">{r[3]}</span>,
              <span className="font-mono text-xs text-muted-foreground">{r[4]}</span>,
              <Badge tone={r[5] === "Active" ? "success" : "muted"}>{r[5]}</Badge>,
            ])}
          />
        </Panel>
      </div>
    </div>
  );
}
