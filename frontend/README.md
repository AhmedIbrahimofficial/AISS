# AISS Core Guardian

Build a dark-themed, real-time Security Operations Center (SOC) dashboard called "AISS — Artificial Intelligence Security System". This is a cybersecurity threat monitoring and AI-powered auto-response platform.

=== OVERALL AESTHETIC ===

Futuristic cyberpunk command-center UI. Dark, glowing, data-dense but clean. Feels like a NASA mission control / Mr. Robot SOC screen. Everything glows subtly against near-black background. Use glassmorphism panels with thin luminous borders and soft inner shadows.

=== COLOR PALETTE (exact hex) ===

Background base: #0A0E17 (near-black navy)

Panel background: #10151F with 60-70% opacity + backdrop-blur

Panel border: 1px solid rgba(0, 217, 255, 0.15) with subtle glow on hover

Primary accent (cyan/teal — main data, network lines, links): #00D9FF and #00FFC2

Critical/danger (ransomware, brute force, intrusion): #FF3B3B / #FF453A

Warning/medium (suspicious activity): #FFB020 / #FF9500

Success/resolved/safe: #00FF88 / #30D97F

Info/secondary category: #A855F7 (purple) — used for campaign/correlation markers

Text primary: #E8EEF5 (off-white)

Text secondary/muted: #6B7A90

Grid lines / dividers: rgba(255,255,255,0.06)

All charts, gauges, and glowing elements should use these colors consistently — cyan = normal/external traffic, red = critical threat, orange = medium, green = resolved/contained, purple = correlated campaign.

=== LAYOUT STRUCTURE ===

Top bar: Logo "AISS" + live system status pill (green pulsing dot "SYSTEM ONLINE") + current date/time + user avatar.

Row 1 — KPI Strip (5-6 small stat cards, horizontal):

- Active Threats (large number, red if >0)

- Threats Blocked Today

- Critical Alerts (red badge)

- Avg Response Time (e.g. "4.2s")

- Network Health (mini sparkline)

- AI Confidence Score (circular mini gauge, teal)

Row 2 — Main visualization (2/3 + 1/3 split):

Left (2/3 width): Large glowing line/area chart — "Threat Activity — External vs Internal" — dual-line chart, cyan line for external, red/orange for internal, filled gradient under lines, smooth curves, glowing line stroke, last 24h with hoverable tooltips.

Right (1/3 width): World map (dark, minimal country outlines in low-opacity teal) showing live attack origin points connected by animated glowing arc lines (cyan/purple/orange) to destination — represents live attack traffic geolocation. Below map: mini radial gauge showing overall threat score (e.g. "94" in center, segmented ring in green/yellow/red).

Row 3 — Detection & Response widgets (3-4 column grid):

- Heatmap grid widget: small colored squares (cyan/orange/purple/red) representing threat density across time/source — like a GitHub contribution graph but with severity colors

- Live threat feed list: scrolling list of recent events with colored severity dot + threat type + source IP + timestamp (e.g. "🔴 Brute Force SSH — 192.168.1.104", "🟠 Malware Signature — EPA-694")

- Response status board: kanban-style columns (Containing / Investigating / Mitigated / Monitoring / Escalated / Resolved) each with colored count badges

- Auto-response timeline: horizontal timeline/slider showing recent automated actions with timestamps

- Audio/frequency-style bar visualizer (vertical bars, purple-to-cyan gradient) representing live network packet activity — decorative but data-driven feel

Row 4 (optional, smaller): Horizontal progress bars for module health — Network Monitor, Auth Monitor, File Monitor, Malware Scanner, AI Firewall — each a thin glowing bar showing "active/scanning" status in green.

=== TYPOGRAPHY ===

Font: Inter or Space Grotesk for UI text, JetBrains Mono or Roboto Mono for numbers/data/IPs/timestamps (gives that terminal/technical feel).

KPI numbers: large, bold, slightly glowing text-shadow in their status color.

Labels: small, uppercase, letter-spaced, muted gray (#6B7A90).

=== VISUAL EFFECTS ===

- Subtle glow (box-shadow / filter: drop-shadow) on all chart lines, active status dots, and gauge rings — matching their color

- Glassmorphism: backdrop-filter: blur(12px), semi-transparent panel backgrounds

- Live pulse animation on "SYSTEM ONLINE" dot and on active/critical threat indicators

- Smooth chart line animations on load (draw-in effect)

- Hover states: panel border brightens, slight scale-up (1.01)

- Map arc lines animate (dash-offset traveling glow) to simulate live traffic

- Number counters animate/count-up on load

=== DATA CONTEXT (use realistic placeholder data matching this domain) ===

Threat types to reference: Port Scan, Brute Force SSH, Malware Signature, C2 Traffic, Ransomware, Data Exfiltration, DDoS, Trojan, Credential Stuffing, APT Chain Detected.

Show severity levels: CRITICAL, HIGH, MEDIUM, LOW with the color mapping above.

Include a "Campaign Detected" badge (purple) occasionally to represent correlated multi-threat attacks.

=== TECH NOTES ===

Fully responsive, dashboard should work on a wide monitor (primary) and gracefully collapse to single column on smaller screens. Use a charting library (Recharts or similar) for line/area/radial charts. All mock data should update/animate periodically to feel "live" (simulate WebSocket feed with setInterval).

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/7494fde3-2767-427c-b30d-df3e8176543e).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
