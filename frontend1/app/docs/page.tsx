"use client";
import { useState } from "react";
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
                onClick={() => setActive(s.id)}
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
            <p className="text-white/50 mb-12 text-lg">Complete setup guide for the CyberSec Backend Platform.</p>
          </motion.div>

          <div className="space-y-16">

            {/* ── QUICK START ── */}
            <DocSection id="quickstart" title="⚡ Quick Start (One Command)" active={active}>
              <p className="text-white/50 text-sm mb-6">
                Fastest way to get running — one command does everything.
              </p>

              <Step label="Windows — Double click or run in CMD:">
                <Code lang="bat">{`start.bat`}</Code>
                <p className="text-white/40 text-xs mt-2">
                  Installs dependencies → creates database → launches server
                </p>
              </Step>

              <Step label="Linux / macOS — Run in terminal:">
                <Code lang="bash">{`chmod +x start.sh\n./start.sh`}</Code>
                <p className="text-white/40 text-xs mt-2">
                  Same flow: dependencies → database → server
                </p>
              </Step>

              <div className="cyber-card p-4 mt-4">
                <p className="text-neon text-xs font-bold uppercase tracking-widest mb-2">After launch</p>
                <div className="space-y-1 text-sm">
                  <p className="text-white/60">Backend API → <span className="text-neon font-mono">http://localhost:8000</span></p>
                  <p className="text-white/60">Swagger Docs → <span className="text-neon font-mono">http://localhost:8000/docs</span></p>
                  <p className="text-white/60">Frontend → <span className="text-neon font-mono">http://localhost:3000</span></p>
                </div>
              </div>
            </DocSection>

            {/* ── WINDOWS ── */}
            <DocSection id="windows" title="🪟 Windows Setup (Manual)" active={active}>
              <Step label="1. Clone the repository">
                <Code lang="cmd">{`git clone https://github.com/AhmedIbrahimofficial/cybersecurity-backend.git\ncd cybersecurity-backend`}</Code>
              </Step>

              <Step label="2. Create virtual environment">
                <Code lang="cmd">{`python -m venv venv\nvenv\\Scripts\\activate`}</Code>
              </Step>

              <Step label="3. Install Python dependencies">
                <Code lang="cmd">{`pip install -r requirements.txt`}</Code>
              </Step>

              <Step label="4. Create PostgreSQL database">
                <Code lang="cmd">{`psql -U postgres -c "CREATE DATABASE cybersentinel;"`}</Code>
              </Step>

              <Step label="5. Configure .env file">
                <Code lang="env">{`DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/cybersentinel\nSECRET_KEY=your-long-random-secret\nADMIN_USERNAME=admin\nADMIN_PASSWORD=admin123\nALLOWED_ORIGINS=http://localhost:3000\nFRONTEND_URL=http://localhost:3000`}</Code>
              </Step>

              <Step label="6. Start the backend">
                <Code lang="cmd">{`python main.py`}</Code>
              </Step>

              <Step label="7. Start the frontend (new terminal)">
                <Code lang="cmd">{`cd frontend1\nnpm install\nnpm run dev`}</Code>
              </Step>
            </DocSection>

            {/* ── LINUX ── */}
            <DocSection id="linux" title="🐧 Linux / macOS Setup (Manual)" active={active}>
              <Step label="1. Clone the repository">
                <Code lang="bash">{`git clone https://github.com/AhmedIbrahimofficial/cybersecurity-backend.git\ncd cybersecurity-backend`}</Code>
              </Step>

              <Step label="2. Create virtual environment">
                <Code lang="bash">{`python3 -m venv venv\nsource venv/bin/activate`}</Code>
              </Step>

              <Step label="3. Install Python dependencies">
                <Code lang="bash">{`pip install -r requirements.txt`}</Code>
              </Step>

              <Step label="4. Create PostgreSQL database">
                <Code lang="bash">{`psql -U postgres -c "CREATE DATABASE cybersentinel;"`}</Code>
              </Step>

              <Step label="5. Configure .env file">
                <Code lang="bash">{`cp .env.example .env   # if exists, else create manually\nnano .env`}</Code>
                <Code lang="env">{`DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/cybersentinel\nSECRET_KEY=your-long-random-secret\nADMIN_USERNAME=admin\nADMIN_PASSWORD=admin123\nALLOWED_ORIGINS=http://localhost:3000\nFRONTEND_URL=http://localhost:3000`}</Code>
              </Step>

              <Step label="6. Start the backend">
                <Code lang="bash">{`python main.py\n# or with uvicorn directly:\nuvicorn main:app --host 0.0.0.0 --port 8000 --reload`}</Code>
              </Step>

              <Step label="7. Start the frontend (new terminal)">
                <Code lang="bash">{`cd frontend1\nnpm install\nnpm run dev`}</Code>
              </Step>

              <Step label="8. Make start.sh executable (one time only)">
                <Code lang="bash">{`chmod +x start.sh`}</Code>
              </Step>
            </DocSection>

            {/* ── CONFIG ── */}
            <DocSection id="config" title="⚙️ Configuration (.env)" active={active}>
              <Step label="Full .env reference:">
                <Code lang="env">{`# ── Database ──────────────────────────────────
DATABASE_URL=postgresql://postgres:PASSWORD@localhost:5432/cybersentinel

# ── CORS ──────────────────────────────────────
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173

# ── JWT ───────────────────────────────────────
SECRET_KEY=change-this-to-a-long-random-secret
ACCESS_TOKEN_EXPIRE_MINUTES=10080
REFRESH_TOKEN_EXPIRE_DAYS=30

# ── Admin (auto-created on first run) ─────────
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123

# ── Email (Gmail SMTP) ────────────────────────
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=youremail@gmail.com
SMTP_PASSWORD=your-gmail-app-password
FRONTEND_URL=http://localhost:3000

# ── AI (optional) ─────────────────────────────
# ANTHROPIC_API_KEY=sk-ant-...`}</Code>
              </Step>
            </DocSection>

            {/* ── BACKGROUND / PROD ── */}
            <DocSection id="background" title="🚀 Background / Production" active={active}>
              <Step label="Windows — Run in background (PowerShell):">
                <Code lang="cmd">{`Start-Process python -ArgumentList "main.py" -NoNewWindow`}</Code>
              </Step>

              <Step label="Linux — Using nohup:">
                <Code lang="bash">{`nohup uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4 &`}</Code>
              </Step>

              <Step label="Linux — Using pm2 (recommended):">
                <Code lang="bash">{`npm install -g pm2\npm2 start "uvicorn main:app --host 0.0.0.0 --port 8000" --name cybersec\npm2 startup && pm2 save`}</Code>
              </Step>

              <Step label="Linux — Using systemd:">
                <Code lang="bash">{`# /etc/systemd/system/cybersec.service\n[Unit]\nDescription=CyberSec API\nAfter=network.target\n\n[Service]\nWorkingDirectory=/path/to/cybersecurity-backend\nExecStart=/path/to/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n\nsudo systemctl enable cybersec\nsudo systemctl start cybersec`}</Code>
              </Step>
            </DocSection>

            {/* ── API ── */}
            <DocSection id="api" title="📡 API Reference" active={active}>
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
                      ["POST",   "/api/auth/register",      "Create new account"],
                      ["GET",    "/api/auth/verify-email",  "Verify email via token"],
                      ["POST",   "/api/auth/login",         "Login → get tokens"],
                      ["POST",   "/api/auth/refresh",       "Refresh access token"],
                      ["GET",    "/api/auth/me",            "Current user info"],
                      ["POST",   "/api/auth/forgot-password","Request reset email"],
                      ["POST",   "/api/auth/reset-password","Reset password"],
                      ["GET",    "/api/threats/",           "All threats"],
                      ["GET",    "/api/threats/active",     "Active threats"],
                      ["GET",    "/api/threats/stats",      "Threat statistics"],
                      ["POST",   "/api/scanner/simulate",   "Inject demo threats"],
                      ["POST",   "/api/ai/analyze",         "AI threat analysis"],
                      ["GET",    "/api/health",             "Health check"],
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
            <DocSection id="auth" title="🔐 Authentication" active={active}>
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

function DocSection({ id, title, children, active }: {
  id: string; title: string; children: React.ReactNode; active: string;
}) {
  return (
    <section id={id} className={active === id ? "" : "opacity-50"}>
      <h2 className="text-2xl font-bold text-white mb-6 pb-3 border-b border-white/10">{title}</h2>
      <div className="space-y-6">{children}</div>
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
