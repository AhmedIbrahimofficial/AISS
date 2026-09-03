/**
 * IOC & Threat Intelligence — AISS
 * Real backend connections:
 *  - /api/intel/enrich/ip/:ip  (VT + Shodan)
 *  - /api/intel/ioc/extract    (spaCy + ioc_finder)
 *  - /api/intel/phishing/analyze
 *  - /api/intel/semantic/search
 *  - /api/intel/taxii/stats + ingest
 *  - /api/intel/llm/analyze
 */
import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { Search, Globe, FileText, Shield, RefreshCw, Loader2, Download } from "lucide-react";
import { PageHeader } from "@/components/soc/AppShell";
import { Panel } from "@/components/soc/Panel";
import { Badge, Metric } from "@/components/soc/ui";
import { ActionButton } from "@/components/soc/actions";
import {
  enrichIP, extractIOCs, analyzePhishing, semanticSearch,
  getTaxiiStats, ingestTaxii, llmAnalyze,
  type IPEnrichment, type IOCResult, type PhishingResult, type SemanticResult,
} from "@/lib/api";

export const Route = createFileRoute("/threat-intelligence")({
  head: () => ({
    meta: [
      { title: "IOC & Threat Intelligence — AISS" },
      { name: "description", content: "IP enrichment, IOC extraction, phishing analysis, semantic threat search" },
    ],
  }),
  component: ThreatIntelPage,
});

type TabId = "ip" | "ioc" | "phishing" | "search" | "feeds";

function ThreatIntelPage() {
  const [tab, setTab]           = useState<TabId>("ip");
  const [ipInput, setIpInput]   = useState("");
  const [iocText, setIocText]   = useState("");
  const [urlInput, setUrlInput] = useState("");
  const [searchQ, setSearchQ]   = useState("");
  const [loading, setLoading]   = useState(false);

  const [ipResult,      setIpResult]      = useState<IPEnrichment | null>(null);
  const [iocResult,     setIocResult]     = useState<IOCResult | null>(null);
  const [phishResult,   setPhishResult]   = useState<PhishingResult | null>(null);
  const [searchResults, setSearchResults] = useState<SemanticResult[]>([]);
  const [llmAnalysis,   setLlmAnalysis]   = useState<string>("");

  const { data: taxii, refetch: refetchTaxii } = useQuery({
    queryKey: ["taxii-stats"],
    queryFn: getTaxiiStats,
    refetchInterval: 30_000,
  });

  const run = async () => {
    setLoading(true);
    try {
      if (tab === "ip") {
        if (!ipInput.trim()) { toast.error("Enter an IP address"); return; }
        const r = await enrichIP(ipInput.trim());
        setIpResult(r);
        toast.success(`Enriched ${ipInput}`);
      } else if (tab === "ioc") {
        if (!iocText.trim()) { toast.error("Enter text to extract IOCs from"); return; }
        const r = await extractIOCs(iocText.trim());
        setIocResult(r.iocs);
        const total = Object.values(r.iocs).reduce((a, b) => a + b.length, 0);
        toast.success(`Extracted ${total} IOCs`);
        if (total > 0) {
          const analysis = await llmAnalyze(`Analyze these IOCs for threat context: ${JSON.stringify(r.iocs)}`).catch(() => null);
          if (analysis) {
            setLlmAnalysis(typeof analysis.analysis === "string" ? analysis.analysis : JSON.stringify(analysis.analysis));
          }
        }
      } else if (tab === "phishing") {
        if (!urlInput.trim()) { toast.error("Enter a URL to analyze"); return; }
        const r = await analyzePhishing(urlInput.trim());
        setPhishResult(r);
        toast.success(`Phishing analysis complete: ${r.risk_level}`);
      } else if (tab === "search") {
        if (!searchQ.trim()) { toast.error("Enter a search query"); return; }
        const r = await semanticSearch(searchQ.trim(), 10);
        setSearchResults(r.results);
        toast.success(`${r.count} semantic matches found`);
      }
    } catch (e) {
      toast.error(`Error: ${String(e)}`);
    } finally {
      setLoading(false);
    }
  };

  const handleIngestTaxii = async () => {
    setLoading(true);
    try {
      const r = await ingestTaxii();
      toast.success(`TAXII ingest complete: ${r.ingested} indicators`);
      void refetchTaxii();
    } catch (e) {
      toast.error(`TAXII ingest failed: ${String(e)}`);
    } finally {
      setLoading(false);
    }
  };

  const riskColor = (score: number) =>
    score > 70 ? "critical" : score > 40 ? "warning" : "success";

  const TABS: { id: TabId; label: string }[] = [
    { id: "ip",       label: "IP Enrichment" },
    { id: "ioc",      label: "IOC Extraction" },
    { id: "phishing", label: "Phishing / URL" },
    { id: "search",   label: "Semantic Search" },
    { id: "feeds",    label: "Intel Feeds" },
  ];

  return (
    <div>
      <PageHeader
        title="IOC & Threat Intelligence"
        subtitle="IP reputation, IOC extraction, phishing analysis, semantic threat search and TAXII feeds"
        right={
          <div className="flex items-center gap-2">
            <Badge tone={taxii?.configured ? "success" : "warning"}>
              TAXII {taxii?.configured ? "CONNECTED" : "NOT CONFIGURED"}
            </Badge>
            {taxii?.indicators_cached != null && (
              <Badge tone="info">{taxii.indicators_cached.toLocaleString()} IOCs cached</Badge>
            )}
          </div>
        }
      />

      {/* Tab bar */}
      <div className="mb-4 flex gap-1 border-b border-[var(--hairline)] pb-2 flex-wrap">
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`rounded-md border px-3 py-1.5 font-mono text-[0.62rem] tracking-wider uppercase transition-colors ${
              tab === t.id
                ? "border-primary/40 bg-primary/12 text-primary"
                : "border-transparent text-muted-foreground hover:bg-white/5"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="grid gap-4 xl:grid-cols-12">
        {/* ── Input panel ──────────────────────────────────── */}
        <div className="xl:col-span-4">
          <Panel title={
            tab === "ip" ? "IP Reputation Lookup" :
            tab === "ioc" ? "IOC Extractor" :
            tab === "phishing" ? "Phishing / URL Analyzer" :
            tab === "search" ? "Semantic Threat Search" :
            "Intelligence Feeds"
          }>
            {tab === "ip" && (
              <div className="space-y-3">
                <p className="text-xs text-muted-foreground">
                  Enriches an IP address using VirusTotal, Shodan, and GeoIP — shows reputation, open ports, vulnerabilities, and geographic data.
                </p>
                <input
                  value={ipInput}
                  onChange={e => setIpInput(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && void run()}
                  placeholder="e.g. 45.33.32.156"
                  className="w-full rounded-md border border-[var(--hairline)] bg-white/5 px-3 py-2 font-mono text-sm outline-none focus:border-primary/50"
                />
              </div>
            )}
            {tab === "ioc" && (
              <div className="space-y-3">
                <p className="text-xs text-muted-foreground">
                  Extracts IPs, domains, URLs, hashes, CVEs, email addresses, and MITRE techniques from any text using NLP (spaCy + ioc_finder).
                </p>
                <textarea
                  value={iocText}
                  onChange={e => setIocText(e.target.value)}
                  placeholder="Paste logs, threat reports, email bodies, malware descriptions..."
                  rows={6}
                  className="w-full resize-none rounded-md border border-[var(--hairline)] bg-white/5 px-3 py-2 font-mono text-xs outline-none focus:border-primary/50"
                />
              </div>
            )}
            {tab === "phishing" && (
              <div className="space-y-3">
                <p className="text-xs text-muted-foreground">
                  Analyzes a URL or domain for phishing indicators using heuristics and threat datasets. Returns risk score, flags, and recommendation.
                </p>
                <input
                  value={urlInput}
                  onChange={e => setUrlInput(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && void run()}
                  placeholder="e.g. https://paypa1-secure.evil.com/login"
                  className="w-full rounded-md border border-[var(--hairline)] bg-white/5 px-3 py-2 font-mono text-sm outline-none focus:border-primary/50"
                />
              </div>
            )}
            {tab === "search" && (
              <div className="space-y-3">
                <p className="text-xs text-muted-foreground">
                  Semantic vector search across all stored threats using sentence transformers + ChromaDB. Finds similar threats even with different terminology.
                </p>
                <input
                  value={searchQ}
                  onChange={e => setSearchQ(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && void run()}
                  placeholder="e.g. ransomware lateral movement credential theft"
                  className="w-full rounded-md border border-[var(--hairline)] bg-white/5 px-3 py-2 font-mono text-sm outline-none focus:border-primary/50"
                />
              </div>
            )}
            {tab === "feeds" && (
              <div className="space-y-4">
                <p className="text-xs text-muted-foreground">
                  STIX/TAXII feed management — ingest MITRE ATT&CK intelligence, view cached indicators, and trigger manual refreshes.
                </p>
                <div className="rounded-lg border border-[var(--hairline)] p-3 space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="text-sm font-medium">MITRE ATT&CK TAXII</span>
                    <Badge tone={taxii?.configured ? "success" : "warning"}>{taxii?.configured ? "CONFIGURED" : "NOT SET"}</Badge>
                  </div>
                  <div className="flex justify-between text-xs text-muted-foreground">
                    <span>Indicators cached</span>
                    <span className="font-mono">{taxii?.indicators_cached?.toLocaleString() ?? "0"}</span>
                  </div>
                  <p className="font-mono text-[0.6rem] text-muted-foreground">Auto-refreshes every 6 hours</p>
                </div>
              </div>
            )}

            {tab !== "feeds" ? (
              <button
                onClick={() => void run()}
                disabled={loading}
                className="mt-4 w-full flex items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-primary/90 disabled:opacity-50"
              >
                {loading ? <Loader2 className="size-4 animate-spin" /> : <Search className="size-4" />}
                {loading ? "Analyzing..." : tab === "ip" ? "Enrich IP" : tab === "ioc" ? "Extract IOCs" : tab === "phishing" ? "Analyze URL" : "Search"}
              </button>
            ) : (
              <button
                onClick={() => void handleIngestTaxii()}
                disabled={loading}
                className="mt-4 w-full flex items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-primary/90 disabled:opacity-50"
              >
                {loading ? <Loader2 className="size-4 animate-spin" /> : <RefreshCw className="size-4" />}
                {loading ? "Ingesting..." : "Ingest TAXII Feed Now"}
              </button>
            )}
          </Panel>
        </div>

        {/* ── Results panel ──────────────────────────────────── */}
        <div className="xl:col-span-8 space-y-4">
          {/* IP Enrichment result */}
          {tab === "ip" && ipResult && (
            <>
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <Metric label="Risk Score"     value={String(ipResult.intel.risk_score)} tone={riskColor(ipResult.intel.risk_score)} sub="/100" />
                <Metric label="Country"        value={ipResult.geo.country_code}         tone="info" sub={ipResult.geo.country_name} />
                <Metric label="City"           value={ipResult.geo.city || "Unknown"}    tone="default" />
                <Metric label="Coordinates"    value={`${ipResult.geo.latitude.toFixed(2)}, ${ipResult.geo.longitude.toFixed(2)}`} tone="default" />
              </div>

              <Panel title={`Enrichment — ${ipResult.ip}`} right={
                <Badge tone={riskColor(ipResult.intel.risk_score)}>
                  RISK: {ipResult.intel.risk_score > 70 ? "HIGH" : ipResult.intel.risk_score > 40 ? "MEDIUM" : "LOW"}
                </Badge>
              }>
                <div className="space-y-4">
                  {ipResult.intel.vt && (
                    <div>
                      <p className="label-cap text-[0.6rem] mb-2">VirusTotal Intelligence</p>
                      <div className="rounded-lg border border-[var(--hairline)] bg-white/3 p-3 font-mono text-xs space-y-1 max-h-48 overflow-y-auto">
                        {Object.entries(ipResult.intel.vt as Record<string, unknown>).slice(0, 15).map(([k, v]) => (
                          <div key={k} className="flex gap-3">
                            <span className="text-muted-foreground shrink-0 w-36">{k}</span>
                            <span className="truncate">{String(v)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {ipResult.intel.shodan && (
                    <div>
                      <p className="label-cap text-[0.6rem] mb-2">Shodan Intelligence</p>
                      <div className="rounded-lg border border-[var(--hairline)] bg-white/3 p-3 font-mono text-xs space-y-1 max-h-48 overflow-y-auto">
                        {Object.entries(ipResult.intel.shodan as Record<string, unknown>).slice(0, 15).map(([k, v]) => (
                          <div key={k} className="flex gap-3">
                            <span className="text-muted-foreground shrink-0 w-36">{k}</span>
                            <span className="truncate">{String(v)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {!ipResult.intel.vt && !ipResult.intel.shodan && (
                    <div className="rounded-lg border border-yellow-400/20 bg-yellow-400/5 p-3 text-sm text-yellow-300">
                      VirusTotal and Shodan API keys not configured. Risk score is based on GeoIP only.
                      Configure VIRUSTOTAL_API_KEY and SHODAN_API_KEY in .env for full enrichment.
                    </div>
                  )}
                </div>
              </Panel>
            </>
          )}

          {/* IOC Extraction result */}
          {tab === "ioc" && iocResult && (
            <Panel title="Extracted IOCs" right={
              <Badge tone="info">
                {Object.values(iocResult).reduce((a, b) => a + b.length, 0)} total
              </Badge>
            }>
              <div className="space-y-3">
                {Object.entries(iocResult).map(([type, values]) => {
                  if (!values.length) return null;
                  return (
                    <div key={type}>
                      <p className="label-cap text-[0.6rem] mb-1.5 flex items-center gap-1.5">
                        <span className="uppercase">{type}</span>
                        <Badge tone="info">{values.length}</Badge>
                      </p>
                      <div className="flex flex-wrap gap-1.5">
                        {values.map((v: string, i: number) => (
                          <span key={i} className="rounded border border-[var(--hairline)] bg-white/4 px-2 py-0.5 font-mono text-[0.65rem] text-muted-foreground">
                            {v}
                          </span>
                        ))}
                      </div>
                    </div>
                  );
                })}
                {llmAnalysis && (
                  <div className="mt-3 rounded-lg border border-blue-400/20 bg-blue-400/5 p-3">
                    <p className="label-cap text-[0.6rem] text-blue-400 mb-1.5">AI THREAT CONTEXT</p>
                    <p className="font-mono text-[0.62rem] text-muted-foreground leading-relaxed">{llmAnalysis}</p>
                  </div>
                )}
              </div>
            </Panel>
          )}

          {/* Phishing result */}
          {tab === "phishing" && phishResult && (
            <>
              <div className="grid gap-3 sm:grid-cols-3">
                <Metric label="Risk Score"  value={String(phishResult.risk_score)} tone={riskColor(phishResult.risk_score)} sub="/100" />
                <Metric label="Risk Level"  value={phishResult.risk_level}         tone={riskColor(phishResult.risk_score)} />
                <Metric label="Flags Found" value={String(phishResult.flags.length)} tone={phishResult.flags.length > 0 ? "warning" : "success"} />
              </div>
              <Panel title="Phishing Analysis" right={
                <Badge tone={riskColor(phishResult.risk_score)}>{phishResult.risk_level}</Badge>
              }>
                <div className="space-y-3">
                  <div>
                    <p className="label-cap text-[0.6rem] mb-1">URL</p>
                    <p className="font-mono text-xs break-all text-muted-foreground">{phishResult.url}</p>
                  </div>
                  {phishResult.flags.length > 0 && (
                    <div>
                      <p className="label-cap text-[0.6rem] mb-1.5">Detection Flags</p>
                      <div className="flex flex-wrap gap-1.5">
                        {phishResult.flags.map((f, i) => (
                          <span key={i} className="rounded border border-red-400/30 bg-red-400/10 px-2 py-0.5 font-mono text-[0.62rem] text-red-300">
                            {f}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  <div className="rounded-lg border border-[var(--hairline)] bg-white/3 p-3">
                    <p className="label-cap text-[0.6rem] mb-1">Recommendation</p>
                    <p className="text-sm">{phishResult.recommendation}</p>
                  </div>
                </div>
              </Panel>
            </>
          )}

          {/* Semantic search results */}
          {tab === "search" && searchResults.length > 0 && (
            <Panel title="Semantic Search Results" right={
              <Badge tone="info">{searchResults.length} matches</Badge>
            }>
              <div className="space-y-2">
                {searchResults.map((r, i) => (
                  <div key={r.id} className="rounded-lg border border-[var(--hairline)] p-3 hover:bg-white/4">
                    <div className="flex items-start justify-between gap-3 mb-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[0.6rem] text-muted-foreground">#{i + 1}</span>
                        <Badge tone={r.metadata.severity === "critical" ? "critical" : r.metadata.severity === "high" ? "warning" : "info"}>
                          {r.metadata.severity?.toUpperCase() ?? "?"}
                        </Badge>
                        <Badge tone="default">{r.metadata.type ?? "threat"}</Badge>
                      </div>
                      <span className="font-mono text-[0.6rem] text-muted-foreground shrink-0">
                        similarity: {(r.score * 100).toFixed(1)}%
                      </span>
                    </div>
                    <p className="text-sm text-muted-foreground">{r.document}</p>
                  </div>
                ))}
              </div>
            </Panel>
          )}
          {tab === "search" && searchResults.length === 0 && searchQ && !loading && (
            <Panel title="Semantic Search">
              <p className="text-sm text-muted-foreground text-center py-8">
                No semantic matches found. The semantic store may need to accumulate more threats, or ChromaDB may not be configured.
              </p>
            </Panel>
          )}

          {/* Feeds tab */}
          {tab === "feeds" && (
            <Panel title="Intelligence Feed Status">
              <div className="space-y-3">
                {[
                  { name: "MITRE ATT&CK TAXII", status: taxii?.configured ? "CONNECTED" : "NOT CONFIGURED", count: taxii?.indicators_cached ?? 0, desc: "STIX/TAXII 2.1 feed from MITRE" },
                  { name: "YARA Rules", status: "ACTIVE", count: null, desc: "Local YARA rules for malware detection" },
                  { name: "Sigma Rules", status: "ACTIVE", count: null, desc: "Sigma detection rules loaded" },
                  { name: "VirusTotal", status: "API KEY REQUIRED", count: null, desc: "Set VIRUSTOTAL_API_KEY in .env" },
                  { name: "Shodan", status: "API KEY REQUIRED", count: null, desc: "Set SHODAN_API_KEY in .env" },
                  { name: "MaxMind GeoIP", status: "MMDB FILE REQUIRED", count: null, desc: "Download GeoLite2-City.mmdb" },
                ].map(feed => (
                  <div key={feed.name} className="flex items-start justify-between gap-3 rounded-lg border border-[var(--hairline)] p-3">
                    <div>
                      <p className="text-sm font-medium">{feed.name}</p>
                      <p className="text-xs text-muted-foreground mt-0.5">{feed.desc}</p>
                      {feed.count != null && (
                        <p className="font-mono text-[0.62rem] text-primary mt-0.5">{feed.count.toLocaleString()} indicators</p>
                      )}
                    </div>
                    <Badge tone={
                      feed.status === "CONNECTED" || feed.status === "ACTIVE" ? "success" :
                      feed.status === "NOT CONFIGURED" ? "warning" :
                      "default"
                    }>{feed.status}</Badge>
                  </div>
                ))}
              </div>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
