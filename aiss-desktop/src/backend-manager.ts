/**
 * AISS Desktop — Backend Process Manager
 * Manages the Python backend lifecycle: start, health check, restart, shutdown.
 */
import { spawn, ChildProcess } from "child_process";
import { join } from "path";
import { existsSync } from "fs";
import * as http from "http";

export type BackendState = "stopped" | "starting" | "running" | "error";

export interface BackendManagerOptions {
  /** Path to the AISS root directory (contains 'backend' folder) */
  aissRoot: string;
  /** Backend port (default 8000) */
  port?: number;
  /** Max seconds to wait for health check (default 60) */
  healthTimeoutSecs?: number;
  /** Callback for state changes */
  onStateChange?: (state: BackendState, message: string) => void;
  /** Callback for log output */
  onLog?: (line: string) => void;
}

export class BackendManager {
  private process: ChildProcess | null = null;
  private state: BackendState = "stopped";
  private restartCount = 0;
  private readonly maxRestarts = 3;
  private healthCheckInterval: ReturnType<typeof setInterval> | null = null;

  private readonly aissRoot: string;
  private readonly port: number;
  private readonly healthTimeoutSecs: number;
  private readonly onStateChange?: (state: BackendState, message: string) => void;
  private readonly onLog?: (line: string) => void;

  constructor(opts: BackendManagerOptions) {
    this.aissRoot = opts.aissRoot;
    this.port = opts.port ?? 8000;
    this.healthTimeoutSecs = opts.healthTimeoutSecs ?? 60;
    this.onStateChange = opts.onStateChange;
    this.onLog = opts.onLog;
  }

  getState(): BackendState {
    return this.state;
  }

  private setState(state: BackendState, message: string) {
    this.state = state;
    this.onStateChange?.(state, message);
    this.onLog?.(`[backend-manager] ${state}: ${message}`);
  }

  /**
   * Find the Python executable — prefer venv, fall back to system python.
   */
  private findPython(): string {
    const venvPython = join(this.aissRoot, "backend", ".venv", "Scripts", "python.exe");
    if (existsSync(venvPython)) return venvPython;
    return "python";
  }

  /**
   * Start the backend process.
   */
  async start(): Promise<boolean> {
    if (this.state === "running") return true;

    // Check if already responding (maybe started externally)
    const alreadyRunning = await this.checkHealth();
    if (alreadyRunning) {
      this.setState("running", "Backend already running externally");
      this.startHealthMonitor();
      return true;
    }

    this.setState("starting", "Launching backend process...");

    const python = this.findPython();
    const backendDir = join(this.aissRoot, "backend");
    const mainScript = join(backendDir, "main.py");

    if (!existsSync(mainScript)) {
      this.setState("error", `Backend not found at ${mainScript}`);
      return false;
    }

    return new Promise<boolean>((resolve) => {
      try {
        this.process = spawn(python, ["-u", mainScript], {
          cwd: backendDir,
          env: {
            ...process.env,
            PYTHONIOENCODING: "utf-8",
            PYTHONUNBUFFERED: "1",
          },
          stdio: ["ignore", "pipe", "pipe"],
          windowsHide: true,
        });

        this.process.stdout?.on("data", (data: Buffer) => {
          this.onLog?.(`[backend] ${data.toString().trim()}`);
        });

        this.process.stderr?.on("data", (data: Buffer) => {
          this.onLog?.(`[backend:err] ${data.toString().trim()}`);
        });

        this.process.on("error", (err) => {
          this.setState("error", `Process error: ${err.message}`);
          resolve(false);
        });

        this.process.on("exit", (code) => {
          this.process = null;
          if (this.state !== "stopped") {
            this.setState("stopped", `Process exited with code ${code}`);
            // Auto-restart if crashed
            if (code !== 0 && this.restartCount < this.maxRestarts) {
              this.restartCount++;
              this.onLog?.(`[backend-manager] Auto-restarting (attempt ${this.restartCount}/${this.maxRestarts})...`);
              setTimeout(() => this.start(), 3000);
            }
          }
        });

        // Wait for health check
        this.waitForHealth().then((healthy) => {
          if (healthy) {
            this.restartCount = 0;
            this.setState("running", "Backend is healthy");
            this.startHealthMonitor();
            resolve(true);
          } else {
            this.setState("error", "Backend failed to become healthy");
            resolve(false);
          }
        });
      } catch (err) {
        this.setState("error", `Failed to start: ${String(err)}`);
        resolve(false);
      }
    });
  }

  /**
   * Stop the backend process gracefully.
   */
  async stop(): Promise<void> {
    this.stopHealthMonitor();
    this.setState("stopped", "Stopping backend...");

    if (this.process) {
      // Try graceful shutdown first
      this.process.kill("SIGTERM");
      // Force kill after 5 seconds
      const forceKill = setTimeout(() => {
        if (this.process) {
          this.process.kill("SIGKILL");
        }
      }, 5000);

      await new Promise<void>((resolve) => {
        this.process?.on("exit", () => {
          clearTimeout(forceKill);
          this.process = null;
          resolve();
        });
      });
    }
  }

  /**
   * Restart the backend.
   */
  async restart(): Promise<boolean> {
    await this.stop();
    return this.start();
  }

  /**
   * Check if backend is healthy via HTTP.
   */
  private checkHealth(): Promise<boolean> {
    return new Promise((resolve) => {
      const req = http.get(`http://localhost:${this.port}/api/health`, { timeout: 3000 }, (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      });
      req.on("error", () => resolve(false));
      req.on("timeout", () => { req.destroy(); resolve(false); });
    });
  }

  /**
   * Wait for backend to become healthy.
   */
  private async waitForHealth(): Promise<boolean> {
    const deadline = Date.now() + this.healthTimeoutSecs * 1000;
    while (Date.now() < deadline) {
      const healthy = await this.checkHealth();
      if (healthy) return true;
      await new Promise((r) => setTimeout(r, 2000));
    }
    return false;
  }

  /**
   * Start periodic health monitoring.
   */
  private startHealthMonitor() {
    this.stopHealthMonitor();
    this.healthCheckInterval = setInterval(async () => {
      const healthy = await this.checkHealth();
      if (!healthy && this.state === "running") {
        this.setState("error", "Backend became unresponsive");
        // Attempt auto-restart
        if (this.restartCount < this.maxRestarts) {
          this.restartCount++;
          this.onLog?.(`[backend-manager] Auto-restarting after health failure (${this.restartCount}/${this.maxRestarts})...`);
          await this.restart();
        }
      }
    }, 15000);
  }

  private stopHealthMonitor() {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }
  }
}
