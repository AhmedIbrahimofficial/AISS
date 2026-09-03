/**
 * ScheduledTasksPanel — manage recurring security tasks
 * Requirements: 12.1–12.3
 */
import React, { useEffect, useState } from "react";
import agentApi, { type ScheduledTask } from "../../api/agentApi";

export function ScheduledTasksPanel() {
  const [tasks, setTasks] = useState<ScheduledTask[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({
    name: "", description: "", tool_or_playbook: "",
    schedule_expression: "interval:86400", enabled: true,
  });

  useEffect(() => { loadTasks(); }, []);

  const loadTasks = async () => {
    setLoading(true);
    try {
      const res = await agentApi.listScheduled();
      setTasks(res.items);
    } catch (e: unknown) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name || !form.tool_or_playbook || !form.schedule_expression) return;
    setError(null);
    try {
      await agentApi.createScheduled(form);
      setShowForm(false);
      setForm({ name: "", description: "", tool_or_playbook: "", schedule_expression: "interval:86400", enabled: true });
      await loadTasks();
    } catch (err: unknown) {
      setError((err as Error).message);
    }
  };

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Delete scheduled task "${name}"?`)) return;
    try {
      await agentApi.deleteScheduled(id);
      setTasks((p) => p.filter((t) => t.id !== id));
    } catch (err: unknown) {
      setError((err as Error).message);
    }
  };

  const fmtDate = (iso?: string) => iso ? new Date(iso).toLocaleString() : "—";

  return (
    <div className="bg-gray-950 rounded-xl border border-gray-800 overflow-hidden">
      {/* Header */}
      <div className="px-5 py-3 border-b border-gray-800 bg-gray-900 flex items-center gap-3">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-purple-400">
          <circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" />
        </svg>
        <span className="text-sm font-semibold text-gray-200">Scheduled Tasks</span>
        <button
          onClick={() => setShowForm(!showForm)}
          className="ml-auto px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-medium transition-colors"
        >
          {showForm ? "Cancel" : "+ Add Task"}
        </button>
      </div>

      {error && <div className="px-5 py-2 bg-red-900/20 border-b border-red-900 text-red-300 text-xs">{error}</div>}

      {/* Add form */}
      {showForm && (
        <form onSubmit={handleCreate} className="px-5 py-4 border-b border-gray-800 bg-gray-900/50 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-gray-400 block mb-1">Task Name *</label>
              <input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="e.g. Daily Vuln Check"
                required
                className="w-full bg-gray-800 text-gray-200 text-sm px-3 py-2 rounded-lg border border-gray-700 focus:outline-none focus:border-purple-500"
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">Tool / Playbook *</label>
              <input
                value={form.tool_or_playbook}
                onChange={(e) => setForm({ ...form, tool_or_playbook: e.target.value })}
                placeholder="e.g. get_vulnerabilities"
                required
                className="w-full bg-gray-800 text-gray-200 text-sm px-3 py-2 rounded-lg border border-gray-700 focus:outline-none focus:border-purple-500"
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-gray-400 block mb-1">Schedule *</label>
              <input
                value={form.schedule_expression}
                onChange={(e) => setForm({ ...form, schedule_expression: e.target.value })}
                placeholder="interval:86400 or cron:0 9 * * *"
                required
                className="w-full bg-gray-800 text-gray-200 text-sm px-3 py-2 rounded-lg border border-gray-700 focus:outline-none focus:border-purple-500 font-mono"
              />
              <p className="text-xs text-gray-600 mt-1">Examples: interval:3600 (hourly) | interval:86400 (daily)</p>
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">Description</label>
              <input
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                placeholder="Optional description"
                className="w-full bg-gray-800 text-gray-200 text-sm px-3 py-2 rounded-lg border border-gray-700 focus:outline-none focus:border-purple-500"
              />
            </div>
          </div>
          <div className="flex items-center justify-between">
            <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                className="accent-purple-500"
              />
              Enable immediately
            </label>
            <button type="submit" className="px-4 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-sm font-medium transition-colors">
              Create Task
            </button>
          </div>
        </form>
      )}

      {/* Task list */}
      {loading ? (
        <div className="px-5 py-6 text-center text-gray-500 text-sm">Loading…</div>
      ) : tasks.length === 0 ? (
        <div className="px-5 py-6 text-center text-gray-500 text-sm">No scheduled tasks. Click "+ Add Task" to create one.</div>
      ) : (
        <div className="divide-y divide-gray-800/50">
          {tasks.map((t) => (
            <div key={t.id} className="px-5 py-3 flex items-start gap-3 hover:bg-gray-900/30 transition-colors">
              <div className={`mt-1 w-2 h-2 rounded-full shrink-0 ${t.enabled ? "bg-green-400" : "bg-gray-600"}`} />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-gray-200 truncate">{t.name}</p>
                <p className="text-xs text-gray-500 font-mono">{t.tool_or_playbook} · {t.schedule_expression}</p>
                <p className="text-xs text-gray-600 mt-0.5">
                  Last: {fmtDate(t.last_run_at)} · Next: {fmtDate(t.next_run_at)}
                </p>
              </div>
              <button
                onClick={() => handleDelete(t.id, t.name)}
                className="shrink-0 text-xs px-2 py-1 rounded bg-red-600/20 text-red-400 hover:bg-red-600/40 transition-colors border border-red-600/20"
              >
                Delete
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
