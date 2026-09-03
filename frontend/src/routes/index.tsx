import { createFileRoute } from "@tanstack/react-router";
import { toast } from "sonner";
import { KpiStrip } from "@/components/soc/KpiStrip";
import { ThreatChart } from "@/components/soc/ThreatChart";
import { AttackMap } from "@/components/soc/AttackMap";
import { ThreatFeed } from "@/components/soc/ThreatFeed";
import { ResponseBoard } from "@/components/soc/ResponseBoard";
import { AutoResponseTimeline } from "@/components/soc/AutoResponseTimeline";
import { ModuleHealth } from "@/components/soc/ModuleHealth";
import { Heatmap } from "@/components/soc/Heatmap";
import { PacketVisualizer } from "@/components/soc/PacketVisualizer";
import { KillChain } from "@/components/soc/KillChain";
import { SocChatPanel } from "@/components/soc/SocChatPanel";
import { LiveProcessMonitor } from "@/components/soc/LiveProcessMonitor";
import { LiveFileScanner } from "@/components/soc/LiveFileScanner";
import { LiveDiskPanel, LiveNetworkIOPanel } from "@/components/soc/LiveSystemOverview";
import { LiveScannerFeed } from "@/components/soc/LiveScannerFeed";
import { PageHeader } from "@/components/soc/AppShell";
import { Badge } from "@/components/soc/ui";
import { ActionButton } from "@/components/soc/actions";
import { JobTracker } from "@/components/soc/JobTracker";
import { useStartSecurityScan, useStartEicarTest, useVerifyPipeline } from "@/hooks/useAISS";
import {
  BlocklistTicker,
  ComplianceSnapshot,
  IntelFeeds,
  MitreCoverage,
  PlaybookRuns,
  SeverityDonut,
  ShiftRoster,
  SlaGauges,
  TopAttackers,
  VectorBars,
  VulnPosture,
} from "@/components/soc/widgets";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Security Overview — AISS Operations Console" },
      {
        name: "description",
        content:
          "Live SOC overview: active threats, blocked attacks, AI containment latency, MITRE coverage, attack geolocation and module health.",
      },
      { property: "og:title", content: "Security Overview — AISS" },
      {
        property: "og:description",
        content: "Live security operations overview with AI-powered automated threat response.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Dashboard,
});

function Dashboard() {
  const startScan  = useStartSecurityScan();
  const startEicar = useStartEicarTest();
  const verifyPipe = useVerifyPipeline();

  return (
    <div>
      <PageHeader
        title="Security Overview"
        subtitle="Real-time posture across detection, response and infrastructure"
        right={
          <div className="flex shrink-0 items-center gap-2">
            <ActionButton
              label="Full Scan"
              tone="info"
              onClick={() => startScan.mutate({ description: "Dashboard full scan" })}
            />
            <ActionButton
              label="EICAR Test"
              tone="warning"
              onClick={() => startEicar.mutate()}
            />
            <ActionButton
              label="Verify Pipeline"
              tone="success"
              onClick={() => {
                verifyPipe.mutate(undefined, {
                  onSuccess: (res) => {
                    if (res.data.verified) {
                      toast.success("Pipeline verified — EICAR detection confirmed");
                    } else {
                      toast.error("Pipeline verification failed", { description: res.data.error });
                    }
                  },
                });
              }}
            />
            <Badge tone="info">AUTO-RESPONSE ON</Badge>
            <Badge tone="success">DEFCON 4 — Normal</Badge>
          </div>
        }
      />

      <div className="flex flex-col gap-3">
        <KpiStrip />

        {/* Primary visualisation row */}
        <div className="grid items-stretch gap-3 xl:grid-cols-12">
          <div className="xl:col-span-7">
            <ThreatChart />
          </div>
          <div className="xl:col-span-3">
            <AttackMap />
          </div>
          <div className="grid gap-3 xl:col-span-2">
            <SeverityDonut />
            <PacketVisualizer />
          </div>
        </div>

        {/* Detection + response row */}
        <div className="grid items-stretch gap-3 xl:grid-cols-12">
          <div className="xl:col-span-5">
            <ThreatFeed />
          </div>
          <div className="xl:col-span-4">
            <ResponseBoard />
          </div>
          <div className="xl:col-span-3">
            <BlocklistTicker />
          </div>
        </div>

        {/* Intelligence row */}
        <div className="grid items-stretch gap-3 lg:grid-cols-2 xl:grid-cols-4">
          <MitreCoverage />
          <TopAttackers />
          <VectorBars />
          <SlaGauges />
        </div>

        {/* Operations row */}
        <div className="grid items-stretch gap-3 lg:grid-cols-2 xl:grid-cols-4">
          <PlaybookRuns />
          <IntelFeeds />
          <VulnPosture />
          <ShiftRoster />
        </div>

        {/* Timeline + density */}
        <div className="grid items-stretch gap-3 xl:grid-cols-12">
          <div className="xl:col-span-8">
            <AutoResponseTimeline />
          </div>
          <div className="xl:col-span-4">
            <ComplianceSnapshot />
          </div>
        </div>

        <div className="grid items-stretch gap-3 xl:grid-cols-12">
          <div className="xl:col-span-7">
            <Heatmap />
          </div>
          <div className="xl:col-span-5">
            <ModuleHealth />
          </div>
        </div>

        {/* Job tracker + Kill chain + SOC chat */}
        <div className="grid items-stretch gap-3 xl:grid-cols-12">
          <div className="xl:col-span-3">
            <JobTracker />
          </div>
          <div className="xl:col-span-4">
            <KillChain />
          </div>
          <div className="xl:col-span-5">
            <SocChatPanel />
          </div>
        </div>

        {/* ── LIVE PC DATA ─────────────────────────────────────── */}
        {/* Disk + Network I/O side by side */}
        <div className="grid items-stretch gap-3 xl:grid-cols-2">
          <LiveDiskPanel />
          <LiveNetworkIOPanel />
        </div>

        {/* Live process monitor — full width */}
        <LiveProcessMonitor />

        {/* Live file scanner — full width */}
        <LiveFileScanner />

        {/* ── SCI-FI LIVE SCANNER FEED — streaming real events ── */}
        <LiveScannerFeed />
      </div>
    </div>
  );
}
