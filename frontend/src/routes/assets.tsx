import { createFileRoute } from "@tanstack/react-router";
import { PageHeader } from "@/components/soc/AppShell";
import { Panel } from "@/components/soc/Panel";
import { Badge, Bar, DataTable, Metric } from "@/components/soc/ui";

export const Route = createFileRoute("/assets")({
  head: () => ({
    meta: [
      { title: "Assets & Endpoints — AISS Security Console" },
      {
        name: "description",
        content:
          "Inventory of servers, endpoints and cloud workloads with agent health, patch level and risk score.",
      },
      { property: "og:title", content: "Assets & Endpoints — AISS" },
      {
        property: "og:description",
        content: "Endpoint inventory with agent health, patch level and risk scoring.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: AssetsPage,
});

const ASSETS = [
  ["DC-01", "Domain Controller", "Windows Server 2022", "Protected", 12, "Current"],
  ["FS-04", "File Server", "Windows Server 2019", "At Risk", 78, "2 pending"],
  ["EPA-233", "Workstation", "Windows 11", "Quarantined", 91, "5 pending"],
  ["K8S-PROD-A", "Cluster Node", "Ubuntu 22.04", "Protected", 22, "Current"],
  ["VPN-GW", "Gateway", "pfSense 2.7", "Monitored", 44, "1 pending"],
  ["DB-CORE", "Database", "PostgreSQL 16", "Protected", 18, "Current"],
  ["EPA-118", "Workstation", "macOS 15", "Protected", 26, "Current"],
  ["S3-ARCHIVE", "Cloud Storage", "AWS", "Monitored", 35, "N/A"],
];

const stateTone: Record<string, string> = {
  Protected: "success",
  Monitored: "info",
  "At Risk": "warning",
  Quarantined: "critical",
};

function AssetsPage() {
  return (
    <div>
      <PageHeader
        title="Assets & Endpoints"
        subtitle="Coverage, agent health and risk exposure across the estate"
      />

      <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Managed Assets" value="1,482" sub="+18 this week" />
        <Metric label="Agent Coverage" value="98.2%" tone="success" sub="27 unmanaged" />
        <Metric label="At Risk" value="34" tone="warning" sub="unpatched or drifted" />
        <Metric label="Quarantined" value="3" tone="critical" />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel className="p-4 xl:col-span-2" title="Asset Inventory">
          <DataTable
            columns={["Asset", "Role", "Platform", "State", "Risk", "Patch"]}
            rows={ASSETS.map((r) => [
              <span className="font-mono text-xs">{r[0]}</span>,
              r[1],
              <span className="text-muted-foreground">{r[2]}</span>,
              <Badge tone={stateTone[r[3] as string] ?? "muted"}>{r[3]}</Badge>,
              <div className="flex w-24 items-center gap-2">
                <Bar
                  value={r[4] as number}
                  tone={
                    (r[4] as number) > 70
                      ? "var(--critical)"
                      : (r[4] as number) > 40
                        ? "var(--warning)"
                        : "var(--teal)"
                  }
                />
                <span className="font-mono text-[0.65rem] text-muted-foreground">{r[4]}</span>
              </div>,
              <span className="text-xs text-muted-foreground">{r[5]}</span>,
            ])}
          />
        </Panel>

        <Panel className="p-4" title="Coverage by Segment">
          <ul className="space-y-4">
            {[
              ["Corporate endpoints", 99],
              ["Production servers", 100],
              ["Cloud workloads", 96],
              ["OT / IoT devices", 81],
              ["Contractor devices", 74],
            ].map(([name, pct]) => (
              <li key={name as string}>
                <div className="mb-1.5 flex items-center justify-between text-xs">
                  <span>{name}</span>
                  <span className="font-mono text-muted-foreground">{pct}%</span>
                </div>
                <Bar value={pct as number} />
              </li>
            ))}
          </ul>
        </Panel>
      </div>
    </div>
  );
}
