/**
 * AISS Desktop — Preload Script
 * Secure IPC bridge between Electron main process and renderer.
 */
import { contextBridge, ipcRenderer } from "electron";

contextBridge.exposeInMainWorld("aissDesktop", {
  /** Get the AISS version */
  getVersion: () => ipcRenderer.invoke("get-version"),

  /** Check backend status */
  getBackendStatus: () => ipcRenderer.invoke("get-backend-status"),

  /** Restart backend */
  restartBackend: () => ipcRenderer.invoke("restart-backend"),

  /** Open external URL in default browser */
  openExternal: (url: string) => ipcRenderer.invoke("open-external", url),

  /** Listen for backend state changes */
  onBackendState: (callback: (state: string, message: string) => void) => {
    ipcRenderer.on("backend-state", (_event, state, message) => callback(state, message));
  },

  /** Platform info */
  platform: process.platform,
  isDesktop: true,
});
