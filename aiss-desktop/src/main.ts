/**
 * AISS Desktop — Electron Main Process
 * Launches backend, shows splash screen, loads frontend when ready.
 */
import { app, BrowserWindow, Tray, Menu, nativeImage, shell } from "electron";
import { join } from "path";
import { existsSync } from "fs";
import { BackendManager, BackendState } from "./backend-manager";

// ── Paths ───────────────────────────────────────────────────────────
const isDev = !app.isPackaged;
const AISS_ROOT = isDev
  ? join(__dirname, "..", "..")              // dev: aiss-desktop/../ = d:\aiss
  : join(process.resourcesPath ?? app.getAppPath(), "..");

const FRONTEND_PORT = 5173;
const BACKEND_PORT = 8000;
const FRONTEND_URL = isDev
  ? `http://localhost:${FRONTEND_PORT}`
  : `http://localhost:${FRONTEND_PORT}`;

// ── Backend Manager ─────────────────────────────────────────────────
let backendManager: BackendManager;
let mainWindow: BrowserWindow | null = null;
let splashWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let isQuitting = false;

function log(msg: string) {
  console.log(`[AISS] ${msg}`);
}

// ── Splash Screen ───────────────────────────────────────────────────
function createSplashWindow() {
  const splashPath = join(__dirname, "..", "splash.html");
  const splashExists = existsSync(splashPath);

  splashWindow = new BrowserWindow({
    width: 480,
    height: 320,
    frame: false,
    transparent: true,
    resizable: false,
    alwaysOnTop: true,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  if (splashExists) {
    splashWindow.loadFile(splashPath);
  } else {
    // Inline splash if no HTML file
    splashWindow.loadURL(`data:text/html;charset=utf-8,
      <html><head><style>
        body{margin:0;background:#0a1310;display:flex;align-items:center;justify-content:center;height:100vh;font-family:monospace;color:#14b8a6}
        .logo{font-size:3rem;font-weight:bold;letter-spacing:0.3em}
        .sub{font-size:0.8rem;color:#64748b;margin-top:0.5rem}
        .loader{width:40px;height:4px;background:#1a2e25;border-radius:2px;margin-top:1.5rem;overflow:hidden;position:relative}
        .loader::after{content:'';position:absolute;width:40%;height:100%;background:#14b8a6;border-radius:2px;animation:slide 1s infinite ease-in-out}
        @keyframes slide{0%{left:-40%}100%{left:100%}}
      </style></head><body>
        <div style="text-align:center">
          <div class="logo">AISS</div>
          <div class="sub">AI Integrated Security System</div>
          <div class="loader"></div>
        </div>
      </body></html>
    `);
  }
}

function updateSplash(message: string) {
  splashWindow?.webContents.executeJavaScript(
    `document.querySelector('.sub') && (document.querySelector('.sub').textContent = ${JSON.stringify(message)})`
  ).catch(() => {});
}

// ── Main Window ─────────────────────────────────────────────────────
function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1024,
    minHeight: 600,
    title: "AISS — AI Integrated Security System",
    backgroundColor: "#0a1310",
    show: false,
    webPreferences: {
      preload: join(__dirname, "preload.js"),
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  mainWindow.loadURL(FRONTEND_URL);

  mainWindow.on("close", (event) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow?.hide();
    }
  });

  mainWindow.on("closed", () => {
    mainWindow = null;
  });

  // Open external links in browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });
}

// ── System Tray ─────────────────────────────────────────────────────
function createTray() {
  // Use a small transparent icon as placeholder (replace with real icon)
  const icon = nativeImage.createFromDataURL(
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAFklEQVQ4T2NkYPj/n4EBCxg1gGE4GwAAT3gEAdGpE9kAAAAASUVORK5CYII="
  );
  tray = new Tray(icon);
  tray.setToolTip("AISS — AI Integrated Security System");

  const contextMenu = Menu.buildFromTemplate([
    {
      label: "Show Dashboard",
      click: () => {
        mainWindow?.show();
        mainWindow?.focus();
      },
    },
    {
      label: "Restart Backend",
      click: async () => {
        log("Restarting backend from tray menu...");
        updateSplash("Restarting backend...");
        await backendManager.restart();
      },
    },
    { type: "separator" },
    {
      label: "Backend Status",
      enabled: false,
      sublabel: backendManager.getState(),
    },
    { type: "separator" },
    {
      label: "Quit",
      click: () => {
        isQuitting = true;
        app.quit();
      },
    },
  ]);

  tray.setContextMenu(contextMenu);
  tray.on("double-click", () => {
    mainWindow?.show();
    mainWindow?.focus();
  });
}

// ── App Lifecycle ───────────────────────────────────────────────────
app.whenReady().then(async () => {
  log(`AISS Desktop starting (root: ${AISS_ROOT})`);

  // Show splash
  createSplashWindow();
  updateSplash("Starting backend...");

  // Initialize backend manager
  backendManager = new BackendManager({
    aissRoot: AISS_ROOT,
    port: BACKEND_PORT,
    onStateChange: (state: BackendState, msg: string) => {
      log(`Backend: ${state} — ${msg}`);
      updateSplash(msg);
    },
    onLog: (line: string) => {
      log(line);
    },
  });

  // Start backend
  const backendOk = await backendManager.start();

  if (!backendOk) {
    updateSplash("Backend failed to start. Check logs.");
    log("ERROR: Backend failed to start.");
    // Keep splash visible for a few seconds then quit
    setTimeout(() => app.quit(), 5000);
    return;
  }

  updateSplash("Loading dashboard...");

  // Create main window and tray
  createMainWindow();
  createTray();

  // Show main window, close splash
  mainWindow?.once("ready-to-show", () => {
    splashWindow?.close();
    splashWindow = null;
    mainWindow?.show();
  });

  // Fallback: close splash after 10 seconds even if ready-to-show doesn't fire
  setTimeout(() => {
    if (splashWindow) {
      splashWindow.close();
      splashWindow = null;
      mainWindow?.show();
    }
  }, 10000);
});

app.on("before-quit", async () => {
  isQuitting = true;
  log("Shutting down...");
  await backendManager.stop();
});

app.on("window-all-closed", () => {
  // On Windows, keep running in tray
});

app.on("activate", () => {
  if (mainWindow) {
    mainWindow.show();
  }
});
