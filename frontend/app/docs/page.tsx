"use client";
import { useState } from "react";
import { useRef } from "react";
import { motion } from "framer-motion";
import { Terminal, BookOpen, Zap, Shield, Database, Lock, Monitor } from "lucide-react";

const SECTIONS = [
  { id: "quickstart", label: "Quick Start",        icon: Zap },
  { id: "windows",    label: "Windows Setup",      icon: Monitor },
  { id: "linux",      label: "Linux / macOS",      icon: Terminal },
  { id: "config",     label: "Configuration",      icon: BookOpen },
  { id: "background", label: "Background / Prod",  icon: Shield },
  { id: "api",        label: "API Reference",       icon: Database },
  { id: "auth",       label: "Authentication",      icon: Lock },
];

export default function DocsPage() {
  const [active, setActive] = useState("quickstart");

  const sectionRefs: Record<string, React.RefObject<HTMLElement | null>> = {
    quickstart: useRef<HTMLElement>(null),
    windows:    useRef<HTMLElement>(null),
    linux:      useRef<HTMLElement>(null),
    config:     useRef<HTMLElement>(null),
    background: useRef<HTMLElement>(null),
    api:        useRef<HTMLElement>(null),
    auth:       useRef<HTMLElement>(null),
  };

  function scrollTo(id: string) {
    setActive(id);
    sectionRefs[id]?.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  return (
    <main className="bg-black min-h-screen pt-24 pb-20">
      <div className="max-w-6xl mx-auto px-6 flex gap-8">

        {/* Sidebar */}
        <aside className="hidden lg:block w-56 flex-shrink-0 pt-8">
          <div className="sticky top-28 space-y-1">
            <p className="text-white/30 text-xs uppercase tracking-widest mb-4">Documentation</p>
            {SECTIONS.map((s) => (
              <button
                key={s.id}
                onClick={() => scrollTo(s.id)}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm text-left transition-all ${
                  active === s.id
                    ? "bg-neon/10 text-neon border border-neon/20"
                    : "text-white/50 hover:text-white hover:bg-white/5"
                }`}
              >
                <s.icon size={15} />
                {s.label}
              </button>
            ))}
          </div>
        </aside>

        {/* Content */}
        <div className="flex-1 pt-8 max-w-3xl">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
            <p className="section-label">Docs</p>
            <h1 className="text-4xl md:text-5xl font-bold text-white mb-3">Getting Started</h1>
            <p className="text-white/50 mb-12 text-lg">Complete setup guide for the AISS Platform.</p>
          </motion.div>

          <div className="space-y-16">

            {/* ── QUICK START ── */}
            <DocSection id="quickstart" title="⚡ Quick Start" active={active} sectionRef={sectionRefs.quickstart}>

              <div className="cyber-card p-5 border border-neon/20 mb-6">
                <p className="text-neon text-xs font-bold uppercase tracking-widest mb-1">The AISS way</p>
                <p className="text-white/60 text-sm leading-relaxed">
                  After setup, you never need to remember a path or command again.
                  Just open any terminal — anywhere on your system — and type <span className="text-neon font-mono font-bold">aiss</span>.
                  Everything starts automatically.
                </p>
              </div>

              <Step label="Step 1 — Clone the repository">
                <Code lang="cmd">{`git clone https://github.com/AhmedIbrahimofficial/aiss-backend.git\ncd aiss-backend`}</Code>
              </Step>

              <Step label="Step 2 — Add aiss to your PATH (run once, as Administrator)">
                <p className="text-white/40 text-xs mb-2">Windows PowerShell (run as Administrator):</p>
                <Code lang="cmd">{`# Replace the path below with where you cloned the repo\n$dir = "C:\\path\\to\\aiss-backend"\n[System.Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";$dir", "User")`}</Code>
                <p className="text-white/40 text-xs mt-3 mb-2">Or double-click <span className="text-neon font-mono">setup_path.bat</span> inside the repo (runs the above automatically).</p>
              </Step>

              <Step label="Step 3 — Close and reopen your terminal, then type:">
                <Code lang="cmd">{`aiss`}</Code>
                <p className="text-white/40 text-xs mt-2">
                  That&apos;s it. AISS will install all dependencies, create the database, and launch the full system automatically — from any folder, any time.
                </p>
              </Step>

              <div className="cyber-card p-4 mt-2">
                <p className="text-neon text-xs font-bold uppercase tracking-widest mb-3">What starts automatically</p>
                <div className="space-y-1.5 text-sm">
                  <p className="text-white/60">✓ Python dependencies installed (first run only)</p>
                  <p className="text-white/60">✓ SQLite database created automatically</p>
                  <p className="text-white/60">✓ All 12 detection modules activated</p>
                  <p className="text-white/60">✓ GUI Threat Monitor window opens</p>
                  <p className="text-white/60">✓ Live terminal feed starts</p>
                  <p className="text-white/60 mt-3">Backend API → <span className="text-neon font-mono">http://localhost:8000</span></p>
                  <p className="text-white/60">Swagger Docs → <span className="text-neon font-mono">http://localhost:8000/docs</span></p>
                  <p className="text-white/60">Frontend → <span className="text-neon font-mono">http://localhost:3000</span></p>
                </div>
              </div>
            </DocSection>

            {/* ── WINDOWS ── */}
            <DocSection id="windows" title="🪟 Windows Setup (Full Guide)" active={active} sectionRef={sectionRefs.windows}>

              <Step label="1. Clone the repository">
                <Code lang="cmd">{`git clone https://github.com/AhmedIbrahimofficial/aiss-backend.git\ncd aiss-backend`}</Code>
              </Step>

              <Step label="2. Make aiss a global command (one time only)">
                <p className="text-white/40 text-xs mb-2">Option A — Double-click <span className="text-neon font-mono">setup_path.bat</span> in the repo folder (easiest).</p>
                <p className="text-white/40 text-xs mb-2">Option B — Run in PowerShell as Administrator:</p>
                <Code lang="cmd">{`$dir = (Get-Location).Path\n[System.Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";$dir", "User")`}</Code>
              </Step>

              <Step label="3. Close terminal, reopen, then run from anywhere:">
                <Code lang="cmd">{`aiss`}</Code>
                <p className="text-white/40 text-xs mt-2">
                  First run: installs Python packages, creates <span className="text-neon font-mono">logs/cybersecurity.db</span>, starts everything.
                  Every run after: launches instantly.
                </p>
              </Step>

              <Step label="4. (Optional) Configure .env for AI features">
                <Code lang="env">{`# Edit the .env file in the repo folder\nANTHROPIC_API_KEY=sk-ant-...   # enables Claude AI analysis\nSECRET_KEY=your-random-secret\nALLOWED_ORIGINS=http://localhost:3000`}</Code>
              </Step>

              <Step label="5. Start the frontend (separate terminal)">
                <Code lang="cmd">{`cd path\\to\\aiss-frontend\nnpm install\nnpm run dev`}</Code>
              </Step>
            </DocSection>

            {/* ── LINUX ── */}
            <DocSection id="linux" title="🐧 Linux / macOS Setup" active={active} sectionRef={sectionRefs.linux}>

              <Step label="1. Clone the repository">
                <Code lang="bash">{`git clone https://github.com/AhmedIbrahimofficial/aiss-backend.git\ncd aiss-backend`}</Code>
              </Step>

              <Step label="2. Make aiss a global command (one time only)">
                <Code lang="bash">{`# Add to PATH permanently\necho 'export PATH="$PATH:'"$(pwd)"'"' >> ~/.bashrc\nsource ~/.bashrc\n\n# For zsh (macOS default):\necho 'export PATH="$PATH:'"$(pwd)"'"' >> ~/.zshrc\nsource ~/.zshrc`}</Code>
              </Step>

              <Step label="3. Make the launcher executable">
                <Code lang="bash">{`chmod +x start.sh`}</Code>
              </Step>

              <Step label="4. Run from anywhere:">
                <Code lang="bash">{`aiss`}</Code>
                <p className="text-white/40 text-xs mt-2">
                  First run installs all dependencies and creates the database automatically.
                </p>
              </Step>

              <Step label="5. (Optional) Configure .env">
                <Code lang="bash">{`nano .env`}</Code>
                <Code lang="env">{`ANTHROPIC_API_KEY=sk-ant-...\nSECRET_KEY=your-random-secret\nALLOWED_ORIGINS=http://localhost:3000`}</Code>
              </Step>
            </DocSection>

            {/* ── CONFIG ── */}
            <DocSection id="config" title="⚙️ Configuration (.env)" active={active} sectionRef={sectionRefs.config}>
              <p className="text-white/50 text-sm mb-6">
                AISS works out of the box with zero config — SQLite is used by default.
                The <span className="text-neon font-mono">.env</span> file is auto-created on first run.
                Only edit it if you want AI features or PostgreSQL.
              </p>
              <Step label="Full .env reference:">
                <Code lang="env">{`# ── Database (SQLite by default, zero setup) ──
DATABASE_URL=sqlite+aiosqlite:///./logs/cybersecurity.db

# ── Switch to PostgreSQL for production ───────
# DATABASE_URL=postgresql://user:password@localhost:5432/aiss

# ── CORS ──────────────────────────────────────
ALLOWED_ORIGINS=http://localhost:3000

# ── JWT ───────────────────────────────────────
SECRET_KEY=change-this-to-a-long-random-secret
ACCESS_TOKEN_EXPIRE_MINUTES=10080
REFRESH_TOKEN_EXPIRE_DAYS=30

# ── Email (optional, for account verification) 
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=youremail@gmail.com
SMTP_PASSWORD=your-gmail-app-password
FRONTEND_URL=http://localhost:3000

# ── Claude AI (optional, enables AI analysis) ─
ANTHROPIC_API_KEY=sk-ant-...`}</Code>
              </Step>
            </DocSection>

            {/* ── BACKGROUND / PROD ── */}
            <DocSection id="background" title="🚀 Background / Production" active={active} sectionRef={sectionRefs.background}>

              <Step label="Windows — Keep running after terminal closes:">
                <Code lang="cmd">{`# Run in PowerShell\nStart-Process python -ArgumentList "main.py" -NoNewWindow`}</Code>
              </Step>

              <Step label="Linux — Using nohup:">
                <Code lang="bash">{`nohup uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4 &`}</Code>
              </Step>

              <Step label="Linux — Using pm2 (recommended):">
                <Code lang="bash">{`npm install -g pm2\npm2 start "uvicorn main:app --host 0.0.0.0 --port 8000" --name aiss\npm2 startup && pm2 save`}</Code>
              </Step>

              <Step label="Linux — Using systemd:">
                <Code lang="bash">{`# /etc/systemd/system/aiss.service\n[Unit]\nDescription=AISS API\nAfter=network.target\n\n[Service]\nWorkingDirectory=/path/to/aiss-backend\nExecStart=/path/to/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n\nsudo systemctl enable aiss\nsudo systemctl start aiss`}</Code>
              </Step>
            </DocSection>

            {/* ── API ── */}
            <DocSection id="api" title="📡 API Reference" active={active} sectionRef={sectionRefs.api}>
              <div className="overflow-x-auto">
                <table className="w-full text-sm border-collapse">
                  <thead>
                    <tr className="border-b border-white/10">
                      <th className="text-left py-3 pr-4 text-white/40 font-normal text-xs uppercase tracking-wider">Method</th>
                      <th className="text-left py-3 pr-4 text-white/40 font-normal text-xs uppercase tracking-wider">Endpoint</th>
                      <th className="text-left py-3 text-white/40 font-normal text-xs uppercase tracking-wider">Description</th>
                    </tr>
                  </thead>
                  <tbody className="text-white/70">
                    {[
                      ["POST",   "/api/auth/register",       "Create new account"],
                      ["GET",    "/api/auth/verify-email",   "Verify email via token"],
                      ["POST",   "/api/auth/login",          "Login → get tokens"],
                      ["POST",   "/api/auth/refresh",        "Refresh access token"],
                      ["GET",    "/api/auth/me",             "Current user info"],
                      ["POST",   "/api/auth/forgot-password","Request reset email"],
                      ["POST",   "/api/auth/reset-password", "Reset password"],
                      ["GET",    "/api/threats/",            "All threats"],
                      ["GET",    "/api/threats/active",      "Active threats"],
                      ["GET",    "/api/threats/stats",       "Threat statistics"],
                      ["POST",   "/api/threats/{id}/resolve","Resolve a threat"],
                      ["GET",    "/api/kill-chain",          "Kill chain stage map"],
                      ["POST",   "/api/scanner/simulate",    "Inject demo threats"],
                      ["POST",   "/api/ai/analyze",          "Claude AI threat analysis"],
                      ["GET",    "/api/network/connections", "Live network connections"],
                      ["GET",    "/api/health",              "Health check"],
                    ].map(([method, endpoint, desc], i) => (
                      <tr key={i} className="border-b border-white/5">
                        <td className="py-3 pr-4">
                          <span className={`font-mono text-xs px-2 py-1 rounded font-bold ${
                            method === "GET"    ? "bg-neon/10 text-neon" :
                            method === "POST"   ? "bg-blue-500/10 text-blue-400" :
                            "bg-red-500/10 text-red-400"
                          }`}>{method}</span>
                        </td>
                        <td className="py-3 pr-4 font-mono text-xs text-white">{endpoint}</td>
                        <td className="py-3 text-white/50 text-sm">{desc}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </DocSection>

            {/* ── AUTH ── */}
            <DocSection id="auth" title="🔐 Authentication" active={active} sectionRef={sectionRefs.auth}>
              <Step label="Register a new account:">
                <Code lang="bash">{`curl -X POST http://localhost:8000/api/auth/register \\\n  -H "Content-Type: application/json" \\\n  -d '{"username":"ahmed","email":"ahmed@example.com","password":"SecurePass123!"}'`}</Code>
              </Step>

              <Step label="Login (get tokens):">
                <Code lang="bash">{`curl -X POST http://localhost:8000/api/auth/login \\\n  -H "Content-Type: application/x-www-form-urlencoded" \\\n  -d "username=ahmed&password=SecurePass123!"\n\n# Response:\n# { "access_token": "eyJ...", "refresh_token": "eyJ...", "token_type": "bearer" }`}</Code>
              </Step>

              <Step label="Use token in requests:">
                <Code lang="bash">{`curl http://localhost:8000/api/threats/ \\\n  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"`}</Code>
              </Step>

              <Step label="WebSocket connection:">
                <Code lang="js">{`const ws = new WebSocket("ws://localhost:8000/ws");\n\nws.onopen = () => {\n  ws.send(JSON.stringify({ action: "auth", token: "YOUR_JWT" }));\n};\n\nws.onmessage = (e) => {\n  const msg = JSON.parse(e.data);\n  if (msg.status === "authenticated") {\n    ws.send(JSON.stringify({ action: "start_monitoring" }));\n  }\n};`}</Code>
              </Step>
            </DocSection>

          </div>
        </div>
      </div>
    </main>
  );
}

// ── Helpers ──────────────────────────────────────────────────────────

function DocSection({ id, title, children, active, sectionRef }: {
  id: string; title: string; children: React.ReactNode; active: string;
  sectionRef?: React.RefObject<HTMLElement | null>;
}) {
  return (
    <section id={id} ref={sectionRef} className="scroll-mt-28">
      <h2 className={`text-2xl font-bold mb-6 pb-3 border-b border-white/10 transition-colors ${active === id ? "text-white" : "text-white/40"}`}>{title}</h2>
      <div className={`space-y-6 transition-opacity ${active === id ? "opacity-100" : "opacity-40"}`}>{children}</div>
    </section>
  );
}

function Step({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-white/60 text-sm font-medium mb-2 flex items-center gap-2">
        <span className="text-neon">▸</span> {label}
      </p>
      {children}
    </div>
  );
}

function Code({ children, lang }: { children: string; lang?: string }) {
  return (
    <pre className="bg-white/5 border border-white/10 rounded-xl p-4 text-sm font-mono overflow-x-auto leading-relaxed"
      style={{ color: lang === "bash" || lang === "cmd" ? "#00ff88" : lang === "env" ? "#ffd166" : "#a8d8ff" }}>
      <code>{children}</code>
    </pre>
  );
}
