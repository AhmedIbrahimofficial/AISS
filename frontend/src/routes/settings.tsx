import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import { PageHeader } from "@/components/soc/AppShell";
import { Panel } from "@/components/soc/Panel";
import { Badge } from "@/components/soc/ui";
import { ActionButton } from "@/components/soc/actions";
import { ModuleHealth } from "@/components/soc/ModuleHealth";
import { SetupWizard } from "@/components/soc/SetupWizard";
import { useWizard, useLibraries, useLLMProviders, useBackendStatus } from "@/hooks/useAISS";

export const Route = createFileRoute("/settings")({
  head: () => ({
    meta: [
      { title: "Settings & Policies — AISS Security Console" },
      { name: "description", content: "Configure AISS policies, integrations and AI providers" },
    ],
  }),
  component: SettingsPage,
});

function Toggle({ label, hint, initial }: { label: string; hint: string; initial: boolean }) {
  const [on, setOn] = useState(initial);
  return (
    <div className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4 border-b border-[var(--hairline)] py-3 last:border-0">
      <div className="min-w-0">
        <p className="text-sm">{label}</p>
        <p className="mt-0.5 text-xs text-muted-foreground">{hint}</p>
      </div>
      <button
        onClick={() => { setOn((v) => !v); toast.success(`${label} ${!on ? "enabled" : "disabled"}`); }}
        aria-pressed={on}
        aria-label={label}
        className={`h-6 w-11 shrink-0 rounded-full border transition-colors ${on ? "border-primary/50 bg-primary/30" : "border-[var(--hairline)] bg-white/6"}`}
      >
        <span className={`block size-4 rounded-full bg-foreground transition-transform ${on ? "translate-x-6" : "translate-x-1"}`} />
      </button>
    </div>
  );
}

function SettingsPage() {
  const [showWizard, setShowWizard] = useState(false);
  const { data: wizard }            = useWizard();
  const { data: libData }           = useLibraries();
  const { data: llmData }           = useLLMProviders();
  const { online }                  = useBackendStatus();

  const completed = wizard?.completed ?? 0;
  const total     = wizard?.total_questions ?? 0;
  const pct       = total > 0 ? Math.round((completed / total) * 100) : 0;

  return (
    <div>
      <PageHeader
        title="Settings & Policies"
        subtitle="Automation guardrails, detection tuning and platform integrations"
        right={
          <ActionButton
            label="Open Configuration Wizard"
            tone="success"
            onClick={() => setShowWizard(true)}
          />
        }
      />

      {showWizard && <SetupWizard onClose={() => setShowWizard(false)} />}

      {/* Configuration progress */}
      <div className="mb-3 panel p-4">
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <p className="text-sm font-medium">AISS Configuration</p>
            <p className="mt-0.5 text-xs text-muted-foreground">
              {completed}/{total} settings configured ·{" "}
              {llmData?.total_providers ? `${llmData.total_providers} LLM provider(s) active` : "No LLM providers — add API keys"}
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-3">
            <div className="h-1.5 w-32 overflow-hidden rounded-full bg-white/8">
              <div className="h-full rounded-full bg-primary transition-all" style={{ width: `${pct}%` }} />
            </div>
            <span className="font-mono text-xs text-muted-foreground">{pct}%</span>
            <Badge tone={online ? "success" : "critical"}>{online ? "backend online" : "backend offline"}</Badge>
          </div>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel className="p-4" title="Auto-Response Policy">
          <Toggle label="Isolate host on critical detection" hint="Network-quarantines the endpoint within 5 seconds" initial />
          <Toggle label="Auto-block malicious IPs"          hint="Pushes deny rules to perimeter firewalls"       initial />
          <Toggle label="Disable compromised accounts"      hint="Requires Tier 3 approval for privileged accounts" initial />
          <Toggle label="Auto-rollback ransomware changes"  hint="Restores affected files from immutable snapshots" initial={false} />
        </Panel>

        <Panel className="p-4" title="Detection Tuning">
          <Toggle label="Behavioural analytics"    hint="UEBA baseline over 30 days"                   initial />
          <Toggle label="Threat intel enrichment"  hint="STIX/TAXII feeds, refreshed every 6h"         initial />
          <Toggle label="Low-confidence alerts"    hint="Surface detections below 70% model confidence" initial={false} />
          <Toggle label="Online ML anomaly scoring" hint="River HalfSpaceTrees — adapts to live traffic" initial />
        </Panel>

        {/* AI providers */}
        <Panel className="p-4" title="AI / LLM Providers">
          {llmData?.providers.length ? (
            <ul className="space-y-2">
              {llmData.providers.map((p) => (
                <li key={p} className="flex items-center gap-2">
                  <span className="size-2 rounded-full bg-[var(--success)]" />
                  <span className="text-sm">{p}</span>
                  <Badge tone="success">active</Badge>
                </li>
              ))}
            </ul>
          ) : (
            <div className="space-y-2">
              <p className="text-xs text-muted-foreground">No LLM providers configured.</p>
              <p className="text-xs text-muted-foreground">Add ANTHROPIC_API_KEY, OPENAI_API_KEY, or GROQ_API_KEY to enable AI analysis.</p>
              <ActionButton label="Open Wizard to Add Keys" tone="success" onClick={() => setShowWizard(true)} />
            </div>
          )}
        </Panel>

        {/* Library integrations */}
        <Panel className="p-4" title="Library Integrations">
          {libData ? (
            <div className="space-y-2">
              <div className="flex gap-2">
                <Badge tone="success">{libData.enabled} enabled</Badge>
                <Badge tone="warning">{libData.disabled} disabled</Badge>
              </div>
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/8">
                <div
                  className="h-full rounded-full bg-primary"
                  style={{ width: `${Math.round((libData.enabled / Math.max(libData.total, 1)) * 100)}%` }}
                />
              </div>
              <p className="text-xs text-muted-foreground">
                {Math.round((libData.enabled / Math.max(libData.total, 1)) * 100)}% of {libData.total} libraries integrated.
                Disabled libraries are missing API keys or optional.
              </p>
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">Connect to backend to view library status.</p>
          )}
        </Panel>
      </div>

      <div className="mt-4">
        <ModuleHealth />
      </div>
    </div>
  );
}
