import { createFileRoute } from "@tanstack/react-router";
import { PageHeader } from "@/components/soc/AppShell";
import { Panel } from "@/components/soc/Panel";
import { Badge, DataTable, Metric } from "@/components/soc/ui";
import { useUsers } from "@/hooks/useAISS";

export const Route = createFileRoute("/users")({
  head: () => ({
    meta: [
      { title: "Users & Access — AISS Security Console" },
      {
        name: "description",
        content:
          "User roster, role assignments, MFA posture and privileged access reviews for the security platform.",
      },
      { property: "og:title", content: "Users & Access — AISS" },
      {
        property: "og:description",
        content: "User roles, MFA posture and privileged access review status.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: UsersPage,
});

function timeAgo(isoStr: string | null): string {
  if (!isoStr) return "Never";
  const diff = Date.now() - new Date(isoStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "Just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

function roleLabel(role: string): string {
  switch (role) {
    case "admin":   return "Admin";
    case "analyst": return "Analyst";
    case "viewer":  return "Viewer";
    default:        return role;
  }
}

function UsersPage() {
  const { data, isLoading, error } = useUsers();
  const users = data?.users ?? [];
  const total = data?.total ?? 0;
  const adminCount = data?.admin_count ?? 0;
  const activeCount = data?.active_count ?? 0;
  const verifiedCount = users.filter((u) => u.is_verified).length;
  const mfaPct = total > 0 ? Math.round((verifiedCount / total) * 100) : 0;

  return (
    <div>
      <PageHeader
        title="Users & Access"
        subtitle="Console roles, authentication posture and privileged access reviews"
      />

      <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric
          label="Console Users"
          value={isLoading ? "\u2026" : String(total)}
          {...(activeCount > 0 ? { sub: `${activeCount} active` } : {})}
        />
        <Metric
          label="Email Verified"
          value={isLoading ? "…" : `${mfaPct}%`}
          tone={mfaPct === 100 ? "success" : mfaPct >= 80 ? "info" : "warning"}
        />
        <Metric
          label="Privileged Accounts"
          value={isLoading ? "…" : String(adminCount)}
          tone={adminCount > 0 ? "warning" : "default"}
          sub="admin role"
        />
        <Metric
          label="Inactive"
          value={isLoading ? "\u2026" : String(total - activeCount)}
          tone={total - activeCount > 0 ? "critical" : "success"}
          {...(total - activeCount > 0 ? { sub: "pending review" } : { sub: "all active" })}
        />
      </div>

      <Panel
        className="p-4"
        title="Console Roster"
        right={
          isLoading ? (
            <span className="font-mono text-[0.6rem] text-muted-foreground">Loading…</span>
          ) : error ? (
            <Badge tone="critical">Error loading users</Badge>
          ) : (
            <Badge tone="info">{total} users</Badge>
          )
        }
      >
        {isLoading ? (
          <div className="flex h-32 items-center justify-center">
            <p className="text-xs text-muted-foreground">Loading user roster…</p>
          </div>
        ) : users.length === 0 ? (
          <div className="flex h-32 items-center justify-center">
            <p className="text-xs text-muted-foreground">No users registered yet.</p>
          </div>
        ) : (
          <DataTable
            columns={["User", "Email", "Role", "Verified", "Last Login", "Sessions", "Status"]}
            rows={users.map((u) => [
              <span className="font-mono text-xs">{u.username}</span>,
              <span className="text-xs text-muted-foreground">{u.email}</span>,
              <Badge
                tone={u.role === "admin" ? "warning" : u.role === "analyst" ? "info" : "default"}
              >
                {roleLabel(u.role)}
              </Badge>,
              u.is_verified ? (
                <Badge tone="success">Yes</Badge>
              ) : (
                <Badge tone="critical">No</Badge>
              ),
              <span className="font-mono text-xs text-muted-foreground">
                {timeAgo(u.last_login_at)}
              </span>,
              <span className="font-mono text-xs">{u.active_sessions}</span>,
              u.is_active ? (
                <Badge tone="success">Active</Badge>
              ) : (
                <Badge tone="muted">Disabled</Badge>
              ),
            ])}
          />
        )}
      </Panel>
    </div>
  );
}
