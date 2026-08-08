import { createFileRoute } from "@tanstack/react-router";
import { PageHeader } from "@/components/soc/AppShell";
import { Panel } from "@/components/soc/Panel";
import { Badge, DataTable, Metric } from "@/components/soc/ui";
import { AutoResponseTimeline } from "@/components/soc/AutoResponseTimeline";

export const Route = createFileRoute("/incidents")({
  head: () => ({
    meta: [
      { title: "Incident Management — AISS Security Console" },
      {
        name: "description",
        content:
          "Track security incidents through triage, containment and resolution with analyst ownership and SLA timers.",
      },
      { property: "og:title", content: "Incident Management — AISS" },
      {
        property: "og:description",
        content: "Incident triage, containment and resolution tracking for the SOC team.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: IncidentsPage,
});

const INCIDENTS = [
  ["INC-2411", "Ransomware staging on FS-04", "CRITICAL", "Containment", "A. Rahman", "00:12"],
  ["INC-2410", "Credential stuffing — VPN gateway", "HIGH", "Investigating", "M. Chen", "00:41"],
  ["INC-2409", "Suspicious PowerShell on EPA-233", "HIGH", "Investigating", "S. Ortega", "01:07"],
  ["INC-2408", "Outbound C2 beacon, subnet 10.0.4.0/24", "CRITICAL", "Escalated", "A. Rahman", "01:55"],
  ["INC-2407", "Phishing cluster — 46 mailboxes", "MEDIUM", "Monitoring", "L. Novak", "03:22"],
  ["INC-2406", "Privilege escalation attempt, DC-01", "HIGH", "Mitigated", "M. Chen", "05:10"],
  ["INC-2405", "Port scan from 45.83.12.77", "LOW", "Resolved", "Auto", "08:44"],
  ["INC-2404", "Malware signature on EPA-118", "MEDIUM", "Resolved", "Auto", "11:30"],
];

const tone: Record<string, string> = {
  CRITICAL: "critical",
  HIGH: "warning",
  MEDIUM: "warning",
  LOW: "info",
};

const stageTone: Record<string, string> = {
  Containment: "warning",
  Investigating: "info",
  Escalated: "critical",
  Monitoring: "info",
  Mitigated: "success",
  Resolved: "success",
};

function IncidentsPage() {
  return (
    <div>
      <PageHeader
        title="Incident Management"
        subtitle="Open cases, ownership and time-to-containment across the SOC"
      />

      <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Open Incidents" value="6" tone="warning" sub="2 breaching SLA" />
        <Metric label="Mean Time to Contain" value="14m" tone="success" sub="target 30m" />
        <Metric label="Escalated to Tier 3" value="1" tone="critical" />
        <Metric label="Closed This Week" value="132" sub="94% auto-resolved" />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel className="p-4 xl:col-span-2" title="Active Case Queue">
          <DataTable
            columns={["Case", "Summary", "Severity", "Stage", "Owner", "Age"]}
            rows={INCIDENTS.map((r) => [
              <span className="font-mono text-xs text-muted-foreground">{r[0]}</span>,
              <span className="whitespace-normal">{r[1]}</span>,
              <Badge tone={tone[r[2]!] ?? "muted"}>{r[2]}</Badge>,
              <Badge tone={stageTone[r[3]!] ?? "muted"}>{r[3]}</Badge>,
              r[4],
              <span className="font-mono text-xs text-muted-foreground">{r[5]}</span>,
            ])}
          />
        </Panel>

        <Panel className="p-4" title="Playbook Coverage">
          <ul className="space-y-3 text-sm">
            {[
              ["Ransomware containment", "Automated"],
              ["Account lockout & reset", "Automated"],
              ["Host isolation", "Automated"],
              ["Legal / regulator notify", "Manual"],
              ["Forensic image capture", "Manual approval"],
            ].map(([name, mode]) => (
              <li key={name} className="flex items-center justify-between gap-3">
                <span className="min-w-0 truncate">{name}</span>
                <Badge tone={mode === "Automated" ? "success" : "muted"}>{mode}</Badge>
              </li>
            ))}
          </ul>
        </Panel>
      </div>

      <div className="mt-4">
        <AutoResponseTimeline />
      </div>
    </div>
  );
}
