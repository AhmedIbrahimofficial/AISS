import { createFileRoute } from "@tanstack/react-router";
import { PageHeader } from "@/components/soc/AppShell";
import { Panel } from "@/components/soc/Panel";
import { Badge, DataTable, Metric } from "@/components/soc/ui";

export const Route = createFileRoute("/users")({
  head: () => ({
    meta: [
      { title: "Users & Access — AISS Security Console" },
      {
        name: "description",
        content:
          "Analyst roster, role assignments, MFA posture and privileged access reviews for the security platform.",
      },
      { property: "og:title", content: "Users & Access — AISS" },
      {
        property: "og:description",
        content: "Analyst roles, MFA posture and privileged access review status.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: UsersPage,
});

function UsersPage() {
  return (
    <div>
      <PageHeader
        title="Users & Access"
        subtitle="Console roles, authentication posture and privileged access reviews"
      />

      <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Console Users" value="38" sub="12 on shift" />
        <Metric label="MFA Enforced" value="100%" tone="success" />
        <Metric label="Privileged Accounts" value="6" tone="warning" sub="reviewed monthly" />
        <Metric label="Dormant Accounts" value="2" tone="critical" sub="pending disable" />
      </div>

      <Panel className="p-4" title="Console Roster">
        <DataTable
          columns={["Analyst", "Role", "Shift", "MFA", "Last Active", "Status"]}
          rows={[
            ["A. Rahman", "Tier 3 — Incident Lead", "Day", "Hardware key", "2m ago", "Online"],
            ["M. Chen", "Tier 2 — Analyst", "Day", "Authenticator", "6m ago", "Online"],
            ["S. Ortega", "Tier 2 — Analyst", "Night", "Authenticator", "4h ago", "Off shift"],
            ["L. Novak", "Tier 1 — Triage", "Day", "Authenticator", "11m ago", "Online"],
            ["K. Adeyemi", "Threat Intel", "Flexible", "Hardware key", "1h ago", "Away"],
            ["Service: aiss-automation", "Automation", "24/7", "mTLS", "now", "Online"],
          ].map((r) => [
            r[0],
            <span className="text-muted-foreground">{r[1]}</span>,
            r[2],
            <span className="font-mono text-xs">{r[3]}</span>,
            <span className="font-mono text-xs text-muted-foreground">{r[4]}</span>,
            <Badge
              tone={r[5] === "Online" ? "success" : r[5] === "Away" ? "warning" : "muted"}
            >
              {r[5]}
            </Badge>,
          ])}
        />
      </Panel>
    </div>
  );
}
