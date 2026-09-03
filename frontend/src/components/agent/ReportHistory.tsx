/**
 * ReportHistory — view, download, and manage security reports
 * Requirements: 10.4–10.8, 10.10, 11.1–11.4
 */
import React, { useEffect, useState } from "react";
import agentApi, { type Report } from "../../api/agentApi";
import { getMe } from "../../lib/api";

export function ReportHistory() {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [userRole, setUserRole] = useState<string>("viewer");

  useEffect(() => {
    loadReports();
    getMe().then((me) => setUserRole(me.role)).catch(() => {});
  }, []);

  const loadReports = async () => {
    setLoading(true);
    try {
      const res = await agentApi.listReports();
      setReports(res.items);
    } catch (e: unknown) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerate = async () => {
    setGenerating(true);
    setError(null);
    try {
      await agentApi.generateReport();
      await new Promise((r) => setTimeout(r, 1500));
      await loadReports();
    } catch (e: unknown) {
      setError((e as Error).message);
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = async (id: string) => {
    try {
      const blob = await agentApi.downloadPdf(id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `security-report-${id.slice(0, 8)}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: unknown) {
      setError((e as Error).message);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Delete this report permanently?")) return;
    try {
      await agentApi.deleteReport(id);
      setReports((p) => p.filter((r) => r.id !== id));
    } catch (e: unknown) {
      setError((e as Error).message);
    }
  };

  const statusBadge = (status: Report["status"]) => {
    const styles = {
      ready:      "bg-green-500/20 text-green-300 border border-green-500/30",
      generating: "bg-blue-500/20 text-blue-300 border border-blue-500/30",
      failed:     "bg-red-500/20 text-red-300 border border-red-500/30",
    };
    return (
      <span className={`px-2 py-0.5 rounded text-xs font-medium ${styles[status]}`}>
        {status === "generating" && <span className="inline-block w-2 h-2 rounded-full bg-blue-400 animate-pulse mr-1" />}
        {status}
      </span>
    );
  };

  const fmt = (iso?: string) => iso ? new Date(iso).toLocaleDateString() : "—";
  const fmtSize = (bytes?: number) => bytes ? `${(bytes / 1024).toFixed(0)} KB` : "—";

  return (
    <div className="bg-gray-950 rounded-xl border border-gray-800 overflow-hidden">
      {/* Header */}
      <div className="px-5 py-3 border-b border-gray-800 bg-gray-900 flex items-center gap-3">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-blue-400">
          <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" /><polyline points="14 2 14 8 20 8" />
        </svg>
        <span className="text-sm font-semibold text-gray-200">Security Reports</span>
        <button
          onClick={handleGenerate}
          disabled={generating}
          className="ml-auto px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-medium transition-colors flex items-center gap-1.5"
        >
          {generating ? (
            <><span className="w-3 h-3 rounded-full border border-white border-t-transparent animate-spin" />Generating…</>
          ) : (
            <>+ Generate Report</>
          )}
        </button>
      </div>

      {error && (
        <div className="px-5 py-2 bg-red-900/20 border-b border-red-900 text-red-300 text-xs">{error}</div>
      )}

      {loading ? (
        <div className="px-5 py-8 text-center text-gray-500 text-sm">Loading reports…</div>
      ) : reports.length === 0 ? (
        <div className="px-5 py-8 text-center">
          <p className="text-gray-500 text-sm">No reports yet.</p>
          <p className="text-gray-600 text-xs mt-1">Click "Generate Report" to create your first security report.</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 bg-gray-900/50">
                <th className="px-4 py-2.5 text-left text-xs font-medium text-gray-400">Period</th>
                <th className="px-4 py-2.5 text-left text-xs font-medium text-gray-400">Status</th>
                <th className="px-4 py-2.5 text-left text-xs font-medium text-gray-400">Generated</th>
                <th className="px-4 py-2.5 text-left text-xs font-medium text-gray-400">Size</th>
                <th className="px-4 py-2.5 text-right text-xs font-medium text-gray-400">Actions</th>
              </tr>
            </thead>
            <tbody>
              {reports.map((r) => (
                <tr key={r.id} className="border-b border-gray-800/50 hover:bg-gray-900/30 transition-colors">
                  <td className="px-4 py-3 text-gray-300 whitespace-nowrap">
                    <span className="text-xs font-mono text-gray-500">#{r.id.slice(0, 6)}</span>
                    <br />
                    <span className="text-xs">{fmt(r.period_start)} – {fmt(r.period_end)}</span>
                  </td>
                  <td className="px-4 py-3">{statusBadge(r.status)}</td>
                  <td className="px-4 py-3 text-xs text-gray-400 whitespace-nowrap">{fmt(r.generated_at)}</td>
                  <td className="px-4 py-3 text-xs text-gray-500">{fmtSize(r.file_size_bytes)}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-2">
                      {r.status === "ready" && (
                        <button
                          onClick={() => handleDownload(r.id)}
                          className="text-xs px-2.5 py-1 rounded-lg bg-blue-600/20 text-blue-300 hover:bg-blue-600/40 border border-blue-600/30 transition-colors"
                        >
                          ↓ PDF
                        </button>
                      )}
                      {userRole === "admin" && (
                        <button
                          onClick={() => handleDelete(r.id)}
                          className="text-xs px-2.5 py-1 rounded-lg bg-red-600/20 text-red-400 hover:bg-red-600/40 border border-red-600/30 transition-colors"
                        >
                          Delete
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
