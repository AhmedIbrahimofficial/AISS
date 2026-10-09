import { promises as fs } from "fs";
import path from "path";
import type {
  AppConfig,
  ApprovalRequest,
  AuditEntry,
  Incident,
  ThreatEvent,
} from "./types";

export interface AissStore {
  config: AppConfig | null;
  threats: ThreatEvent[];
  incidents: Incident[];
  approvals: ApprovalRequest[];
  audit: AuditEntry[];
  quarantine: Array<{ id: string; threatId: string; at: string; name: string; reason: string }>;
  learnedRules: Array<{ id: string; pattern: string; weight: number; at: string; note: string }>;
  chatHistory: Array<{ id: string; role: "user" | "assistant" | "system"; content: string; at: string; toolsUsed?: string[] }>;
}

const EMPTY: AissStore = {
  config: null,
  threats: [],
  incidents: [],
  approvals: [],
  audit: [],
  quarantine: [],
  learnedRules: [],
  chatHistory: [],
};

const DATA_DIR = path.join(process.cwd(), ".data");
const DATA_FILE = path.join(DATA_DIR, "aiss-store.json");

declare global {
  // eslint-disable-next-line no-var
  var __aissStore: AissStore | undefined;
  // eslint-disable-next-line no-var
  var __aissStoreLoaded: boolean | undefined;
}

function memory(): AissStore {
  if (!globalThis.__aissStore) {
    globalThis.__aissStore = structuredClone(EMPTY);
  }
  return globalThis.__aissStore;
}

async function ensureLoaded(): Promise<AissStore> {
  if (globalThis.__aissStoreLoaded) return memory();
  try {
    const raw = await fs.readFile(DATA_FILE, "utf8");
    const parsed = JSON.parse(raw) as AissStore;
    globalThis.__aissStore = { ...EMPTY, ...parsed };
  } catch {
    globalThis.__aissStore = structuredClone(EMPTY);
  }
  globalThis.__aissStoreLoaded = true;
  return memory();
}

async function persist(store: AissStore): Promise<boolean> {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
    await fs.writeFile(DATA_FILE, JSON.stringify(store, null, 2), "utf8");
    return true;
  } catch {
    // Vercel / read-only FS — keep warm-instance memory
    return false;
  }
}

export async function getStore(): Promise<AissStore> {
  return ensureLoaded();
}

export async function updateStore(
  mutator: (store: AissStore) => void,
): Promise<AissStore> {
  const store = await ensureLoaded();
  mutator(store);
  await persist(store);
  return store;
}

export async function isStoreWritable(): Promise<boolean> {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
    const probe = path.join(DATA_DIR, ".write-probe");
    await fs.writeFile(probe, "ok");
    await fs.unlink(probe);
    return true;
  } catch {
    return false;
  }
}

export async function resetStore(): Promise<void> {
  globalThis.__aissStore = structuredClone(EMPTY);
  globalThis.__aissStoreLoaded = true;
  await persist(memory());
}
