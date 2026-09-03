/**
 * Reports — AISS
 * Real backend:
 *  - GET  /api/reports/           — list generated reports
 *  - POST /api/reports/generate   — generate new PDF report
 *  - GET  /api/reports/{id}/pdf   — download PDF
 *  - DELETE /api/reports/{id}     — delete report
 */
import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  FileText, Download, Trash2, RefreshCw, Loader2, BarChart3,
  Plus, Calendar,
} from "lucide-react";
import { PageHeader } from "@/components/soc/AppShell";
import { Panel } from "@/components/soc/Panel";
import { Badge, Metric } from "@/components/soc/ui";
import { ActionButton } from "@/components/soc/actions";
import { ThreatChart } from "@/components/soc/ThreatChart";
import { useThreatStats } from "@/hooks/useAISS";
import { exportThreatsExcel, exportThreatsDashboard } from "@/lib/api";

const BASE = (import.meta.env["VITE_AISS_API_URL"] as string | undefined) ?? "http://localhost:8000";

async function apiFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const tok = localStorage.getItem("aiss_token") ?? "";
  const r = await fetch(`${BASE}${path}`, {
    ...opts,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${tok}`, ...(opts.headers ?? {}) },
  });
  if (!r.ok) {
    const err = await r.json().catch(() => ({ detail: r.statusText })) as { detail?: string };
    throw new Error(err.detail ?? `HTTP ${r.status}`);
  }
  return r.json() as Promise<T>;
}

interface Report {
  id: string; status: string; generated_at?: string; file_size_bytes?: number;
  period_start?: string; period_end?: string; sha256_hash?: string; error_message?: string;
  scope_json?: unknown;
}

export const Route = createFileRoute("/reports")({
  head: () => ({
    meta: [
      { title: "Reports — AISS Security Console" },
      { name: "description", content: "Security reports, threat exports, and PDF generation" },
    ],
  }),
  component: ReportsPage,
});

function ReportsPage() {
  const [generating, setGenerating] = useState(false);
  const [exporting,  setExporting]  = useState<string | null>(null);
  const { data: stats } = useThreatStats();
  const qc = useQueryClient();

  const { data: reportsData, isLoading, refetch } = useQuery({
    queryKey: ["reports"],
    queryFn: async () => {
      const resp = await apiFetch<{ status: string; data: { items: Report[]; total: number } } | { reports: Report[] }>("/api/reports");
      // Handle both response shapes
      if ("data" in resp && resp.data && "items" in resp.data) {
        return { reports: resp.data.items };
      }
      return resp as { reports: Report[] };
    },
    refetchInterval: 15_000,
  });

  const reports = reportsData?.reports ?? [];

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      const now = new Date();
      const start = new Date(now);
      start.setDate(start.getDate() - 30);
      await apiFetch<{ id: string }>("/api/reports/generate", {
        method: "POST",
        body: JSON.stringify({
          period_start: start.toISOString(),
          period_end:   now.toISOString(),
          scope: { type: "full" },
        }),
      });
      toast.success("Report generation started", { description: "PDF will be ready shortly" });
      void refetch();
    } catch (e) {
      toast.error(`Report generation failed: ${String(e)}`);
    } finally {
      setGenerating(false);
    }
  };

  const handleDownloadPdf = async (id: string) => {
    setExporting(id);
    try {
      const tok = localStorage.getItem("aiss_token") ?? "";
      const r = await fetch(`${BASE}/api/reports/${id}/pdf`, {
        headers: { Authorization: `Bearer ${tok}` },
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const blob = await r.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href = url; a.download = `aiss_report_${id.slice(0, 8)}.pdf`; a.click();
      URL.revokeObjectURL(url);
      toast.success("PDF downloaded");
    } catch (e) {
      toast.error(`Download failed: ${String(e)}`);
    } finally {
      setExporting(null);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await apiFetch(`/api/reports/${id}`, { method: "DELETE" });
      toast.success("Report deleted");
      void refetch();
    } catch (e) {
      toast.error(String(e));
    }
  };

  const handleExportExcel = async () => {
    try {
      const r = await exportThreatsExcel();
      const blob = await r.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href = url; a.download = "aiss_threats.xlsx"; a.click();
      URL.revokeObjectURL(url);
      toast.success("Excel downloaded");
    } catch (e) { toast.error(String(e)); }
  };

  const handleExportDashboard = async () => {
    try {
      const r = await exportThreatsDashboard();
      const blob = await r.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href = url; a.download = "aiss_dashboard.html"; a.click();
      URL.revokeObjectURL(url);
      toast.success("Dashboard snapshot downloaded");
    } catch (e) { toast.error(String(e)); }
  };

  return (
    <div>
      <PageHeader
        title="Reports"
        subtitle="Generate PDF security reports, download threat exports, and view report history"
        right={
          <div className="flex gap-2">
            <ActionButton label="Refresh" onClick={() => void refetch()} />
            <ActionButton
              label={generating ? "Generating..." : "Generate PDF Report"}
              tone="success"
              onClick={() => void handleGenerate()}
            />
          </div>
        }
      />

      {/* KPIs */}
      <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Reports Generated" value={String(reports.length)}                       tone="info"    sub="all time" />
        <Metric label="Pending"           value={String(reports.filter(r => r.status === "pending" || r.status === "generating").length)} tone="warning" />
        <Metric label="Completed"         value={String(reports.filter(r => r.status === "completed" || r.status === "ready").length)} tone="success" />
        <Metric label="Active Threats"    value={String(stats?.active ?? 0)}                   tone={stats && stats.active > 0 ? "critical" : "success"} sub="in this period" />
      </div>

      <div className="grid gap-4 xl:grid-cols-12">
        {/* Quick exports */}
        <div className="xl:col-span-4 flex flex-col gap-4">
          <Panel title="Quick Exports">
            <div className="space-y-2">
              <button
                onClick={() => void handleExportExcel()}
                className="w-full flex items-center gap-3 rounded-lg border border-[var(--hairline)] bg-white/3 px-4 py-3 text-left transition-colors hover:bg-white/6"
              >
                <FileText className="size-5 text-green-400 shrink-0" />
                <div>
                  <p className="text-sm font-medium">Threat Data (Excel)</p>
                  <p className="text-xs text-muted-foreground">All threats with details</p>
                </div>
                <Download className="size-4 text-muted-foreground ml-auto shrink-0" />
              </button>
              <button
                onClick={() => void handleExportDashboard()}
                className="w-full flex items-center gap-3 rounded-lg border border-[var(--hairline)] bg-white/3 px-4 py-3 text-left transition-colors hover:bg-white/6"
              >
                <BarChart3 className="size-5 text-blue-400 shrink-0" />
                <div>
                  <p className="text-sm font-medium">Dashboard Snapshot (HTML)</p>
                  <p className="text-xs text-muted-foreground">Full visual dashboard</p>
                </div>
                <Download className="size-4 text-muted-foreground ml-auto shrink-0" />
              </button>
              <button
                onClick={() => void handleGenerate()}
                disabled={generating}
                className="w-full flex items-center gap-3 rounded-lg border border-primary/30 bg-primary/8 px-4 py-3 text-left transition-colors hover:bg-primary/12 disabled:opacity-50"
              >
                {generating
                  ? <Loader2 className="size-5 text-primary shrink-0 animate-spin" />
                  : <Plus className="size-5 text-primary shrink-0" />
                }
                <div>
                  <p className="text-sm font-medium text-primary">{generating ? "Generating..." : "Generate PDF Report"}</p>
                  <p className="text-xs text-muted-foreground">30-day security summary</p>
                </div>
              </button>
            </div>

            <div className="mt-4 rounded-lg border border-[var(--hairline)] bg-white/3 p-3 text-xs text-muted-foreground space-y-1">
              <p className="text-foreground font-medium">PDF Report includes:</p>
              <p>• Executive summary with risk metrics</p>
              <p>• Threat detection breakdown</p>
              <p>• AI analysis findings</p>
              <p>• SHA256 integrity hash</p>
              <p>• Chain of custody information</p>
            </div>
          </Panel>
        </div>

        {/* Report list + chart */}
        <div className="xl:col-span-8 space-y-4">
          <ThreatChart />

          <Panel
            title="Generated Reports"
            right={<Badge tone="info">{reports.length} total</Badge>}
          >
            {isLoading ? (
              <div className="flex h-32 items-center justify-center">
                <div className="size-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
              </div>
            ) : reports.length === 0 ? (
              <div className="flex h-24 flex-col items-center justify-center gap-2 text-muted-foreground">
                <FileText className="size-8 opacity-30" />
                <p className="text-sm">No reports generated yet</p>
                <p className="text-xs opacity-60">Click Generate PDF Report to create the first one</p>
              </div>
            ) : (
              <div className="space-y-2">
                {reports.map((r: Report) => (
                  <div key={r.id} className="flex items-start gap-3 rounded-lg border border-[var(--hairline)] px-3 py-2.5 hover:bg-white/4">
                    <FileText className="size-5 text-muted-foreground mt-0.5 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <Badge tone={r.status === "completed" ? "success" : r.status === "failed" ? "critical" : "warning"}>
                          {r.status.toUpperCase()}
                        </Badge>
                        <span className="font-mono text-[0.6rem] text-muted-foreground">{r.id.slice(0, 12)}</span>
                      </div>
                      {r.generated_at && (
                        <p className="font-mono text-[0.62rem] text-muted-foreground">
                          Generated: {new Date(r.generated_at).toLocaleString()}
                        </p>
                      )}
                      {r.period_start && r.period_end && (
                        <p className="font-mono text-[0.6rem] text-muted-foreground">
                          Period: {new Date(r.period_start).toLocaleDateString()} — {new Date(r.period_end).toLocaleDateString()}
                        </p>
                      )}
                      {r.file_size_bytes != null && (
                        <p className="font-mono text-[0.6rem] text-muted-foreground">
                          Size: {(r.file_size_bytes / 1024).toFixed(1)} KB
                        </p>
                      )}
                      {r.sha256_hash && (
                        <p className="font-mono text-[0.55rem] text-muted-foreground truncate">
                          SHA256: {r.sha256_hash.slice(0, 32)}...
                        </p>
                      )}
                    </div>
                    <div className="flex gap-1.5 shrink-0">
                      {(r.status === "completed" || r.status === "ready") && (
                        <button
                          onClick={() => void handleDownloadPdf(r.id)}
                          disabled={exporting === r.id}
                          className="flex items-center gap-1 rounded border border-primary/30 bg-primary/8 px-2 py-1 font-mono text-[0.6rem] text-primary hover:bg-primary/12 disabled:opacity-50"
                        >
                          {exporting === r.id ? <Loader2 className="size-3 animate-spin" /> : <Download className="size-3" />}
                          PDF
                        </button>
                      )}
                      <button
                        onClick={() => void handleDelete(r.id)}
                        className="flex items-center gap-1 rounded border border-red-400/20 bg-red-400/5 px-2 py-1 font-mono text-[0.6rem] text-red-400 hover:bg-red-400/10"
                      >
                        <Trash2 className="size-3" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}
