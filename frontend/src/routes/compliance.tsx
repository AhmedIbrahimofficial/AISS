import { createFileRoute } from "@tanstack/react-router";
import { PageHeader } from "@/components/soc/AppShell";
import { Panel } from "@/components/soc/Panel";
import { Badge, Bar, DataTable, Metric } from "@/components/soc/ui";

export const Route = createFileRoute("/compliance")({
  head: () => ({
    meta: [
      { title: "Compliance & Controls — AISS Security Console" },
      {
        name: "description",
        content:
          "Framework readiness for ISO 27001, SOC 2, NIST CSF and GDPR with control evidence and open gaps.",
      },
      { property: "og:title", content: "Compliance & Controls — AISS" },
      {
        property: "og:description",
        content: "ISO 27001, SOC 2, NIST CSF and GDPR control readiness with evidence tracking.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: CompliancePage,
});

function CompliancePage() {
  return (
    <div>
      <PageHeader
        title="Compliance & Controls"
        subtitle="Framework readiness, control evidence and open remediation items"
      />

      <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="ISO 27001" value="96%" tone="success" sub="112 / 117 controls" />
        <Metric label="SOC 2 Type II" value="92%" tone="success" sub="audit window open" />
        <Metric label="NIST CSF" value="88%" tone="warning" sub="Respond tier gap" />
        <Metric label="Open Findings" value="9" tone="warning" sub="3 overdue" />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel className="p-4 xl:col-span-2" title="Control Findings">
          <DataTable
            columns={["Control", "Framework", "Finding", "Severity", "Owner", "Due"]}
            rows={[
              ["A.12.4.1", "ISO 27001", "Log retention below 12 months on OT segment", "High", "IT Ops", "Sep 12"],
              ["CC7.2", "SOC 2", "Alert triage evidence not archived", "Medium", "SOC", "Sep 20"],
              ["PR.AC-4", "NIST CSF", "Standing admin rights on 6 accounts", "High", "IAM", "Sep 5"],
              ["Art. 33", "GDPR", "Breach notification runbook untested", "Medium", "Legal", "Oct 1"],
              ["A.8.16", "ISO 27001", "Monitoring gap on contractor devices", "Low", "IT Ops", "Oct 15"],
            ].map((r) => [
              <span className="font-mono text-xs">{r[0]}</span>,
              <span className="text-muted-foreground">{r[1]}</span>,
              <span className="whitespace-normal">{r[2]}</span>,
              <Badge
                tone={r[3] === "High" ? "critical" : r[3] === "Medium" ? "warning" : "info"}
              >
                {r[3]}
              </Badge>,
              r[4],
              <span className="font-mono text-xs text-muted-foreground">{r[5]}</span>,
            ])}
          />
        </Panel>

        <Panel className="p-4" title="Framework Readiness">
          <ul className="space-y-4">
            {[
              ["ISO 27001", 96],
              ["SOC 2 Type II", 92],
              ["NIST CSF", 88],
              ["GDPR", 94],
              ["PCI DSS 4.0", 79],
            ].map(([n, v]) => (
              <li key={n as string}>
                <div className="mb-1.5 flex items-center justify-between text-xs">
                  <span>{n}</span>
                  <span className="font-mono text-muted-foreground">{v}%</span>
                </div>
                <Bar
                  value={v as number}
                  tone={(v as number) < 85 ? "var(--warning)" : "var(--teal)"}
                />
              </li>
            ))}
          </ul>
        </Panel>
      </div>
    </div>
  );
}
