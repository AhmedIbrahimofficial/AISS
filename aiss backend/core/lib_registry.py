"""AISS - Library Registry & Auto-Integration
Detects all installed libraries at startup, initialises them,
downloads required models, validates credentials, and gracefully
disables features when services are unavailable.

Every integration follows the same contract:
  - Returns LibStatus(name, enabled, version, notes)
  - Never raises — failures are caught and logged
  - Credentials/model paths read from env vars

Call:  registry = LibRegistry(); await registry.init_all()
Query: registry.status()   → list[LibStatus]
       registry.is_enabled("sentence_transformers")  → bool
       registry.get("chromadb")  → any initialised client / None
"""
import asyncio
import importlib
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from utils.logger import setup_logger

logger = setup_logger("lib_registry")

DATA_DIR   = Path("data")
MODELS_DIR = DATA_DIR / "models"
DATA_DIR.mkdir(exist_ok=True)
MODELS_DIR.mkdir(exist_ok=True)


# ─────────────────────────────────────────────────────────────────────
# Status dataclass
# ─────────────────────────────────────────────────────────────────────

@dataclass
class LibStatus:
    name:    str
    enabled: bool
    version: str   = ""
    notes:   str   = ""
    client:  Any   = field(default=None, repr=False)

    def to_dict(self) -> dict:
        return {
            "name":    self.name,
            "enabled": self.enabled,
            "version": self.version,
            "notes":   self.notes,
        }


# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────

def _ver(pkg: str) -> str:
    try:
        return importlib.metadata.version(pkg)
    except Exception:
        return ""


def _try_import(name: str) -> Optional[Any]:
    try:
        return importlib.import_module(name)
    except ImportError:
        return None


# ─────────────────────────────────────────────────────────────────────
# Individual library initialisers
# Each returns a LibStatus.
# ─────────────────────────────────────────────────────────────────────

# ── 1. sentence-transformers ──────────────────────────────────────────
async def _init_sentence_transformers() -> LibStatus:
    name = "sentence_transformers"
    try:
        from sentence_transformers import SentenceTransformer
        model_name = os.environ.get("SBERT_MODEL", "all-MiniLM-L6-v2")
        model_path = MODELS_DIR / model_name.replace("/", "_")

        loop   = asyncio.get_event_loop()
        model  = await loop.run_in_executor(
            None, lambda: SentenceTransformer(model_name, cache_folder=str(MODELS_DIR))
        )
        # warm up
        await loop.run_in_executor(None, lambda: model.encode(["warmup"]))
        return LibStatus(name, True, _ver("sentence-transformers"),
                         f"model={model_name}", client=model)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 2. FAISS ─────────────────────────────────────────────────────────
async def _init_faiss() -> LibStatus:
    name = "faiss"
    try:
        import faiss
        # smoke-test: build a tiny index
        idx = faiss.IndexFlatL2(4)
        import numpy as np
        idx.add(np.random.rand(2, 4).astype("float32"))
        return LibStatus(name, True, _ver("faiss-cpu"), "flat L2 index ready", client=faiss)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 3. ChromaDB ───────────────────────────────────────────────────────
async def _init_chromadb() -> LibStatus:
    name = "chromadb"
    try:
        import chromadb
        loop   = asyncio.get_event_loop()
        client = await loop.run_in_executor(
            None,
            lambda: chromadb.PersistentClient(path=str(DATA_DIR / "chroma_db"))
        )
        # ensure threat-intel collection exists
        await loop.run_in_executor(
            None,
            lambda: client.get_or_create_collection("threat_intel")
        )
        return LibStatus(name, True, _ver("chromadb"), "persistent store ready", client=client)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 4. LanceDB ────────────────────────────────────────────────────────
async def _init_lancedb() -> LibStatus:
    name = "lancedb"
    try:
        import lancedb
        loop = asyncio.get_event_loop()
        db   = await loop.run_in_executor(
            None, lambda: lancedb.connect(str(DATA_DIR / "lance_db"))
        )
        return LibStatus(name, True, _ver("lancedb"), "vector store connected", client=db)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 5. Qdrant ─────────────────────────────────────────────────────────
async def _init_qdrant() -> LibStatus:
    name = "qdrant"
    try:
        from qdrant_client import QdrantClient
        host = os.environ.get("QDRANT_HOST", "localhost")
        port = int(os.environ.get("QDRANT_PORT", "6333"))
        # try in-memory mode first (no server needed)
        client = QdrantClient(":memory:")
        return LibStatus(name, True, _ver("qdrant-client"), "in-memory mode", client=client)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 6. LangChain ─────────────────────────────────────────────────────
async def _init_langchain() -> LibStatus:
    name = "langchain"
    try:
        import langchain
        import langchain_core
        return LibStatus(name, True, _ver("langchain"),
                         f"core={_ver('langchain-core')}", client=langchain)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 7. LangGraph ─────────────────────────────────────────────────────
async def _init_langgraph() -> LibStatus:
    name = "langgraph"
    try:
        import langgraph
        return LibStatus(name, True, _ver("langgraph"), client=langgraph)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 8. CrewAI ─────────────────────────────────────────────────────────
async def _init_crewai() -> LibStatus:
    name = "crewai"
    try:
        import crewai
        return LibStatus(name, True, _ver("crewai"), client=crewai)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 9. LiteLLM ───────────────────────────────────────────────────────
async def _init_litellm() -> LibStatus:
    name = "litellm"
    try:
        import litellm
        litellm.set_verbose = False
        # Set provider keys if present
        if os.environ.get("OPENAI_API_KEY"):
            litellm.openai_key = os.environ["OPENAI_API_KEY"]
        if os.environ.get("ANTHROPIC_API_KEY"):
            litellm.anthropic_key = os.environ["ANTHROPIC_API_KEY"]
        if os.environ.get("GROQ_API_KEY"):
            litellm.groq_key = os.environ["GROQ_API_KEY"]
        if os.environ.get("GOOGLE_API_KEY"):
            litellm.gemini_key = os.environ["GOOGLE_API_KEY"]
        return LibStatus(name, True, _ver("litellm"), "multi-provider LLM unified", client=litellm)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 10. Instructor ────────────────────────────────────────────────────
async def _init_instructor() -> LibStatus:
    name = "instructor"
    try:
        import instructor
        return LibStatus(name, True, _ver("instructor"), client=instructor)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 11. Pydantic-AI ───────────────────────────────────────────────────
async def _init_pydantic_ai() -> LibStatus:
    name = "pydantic_ai"
    try:
        import pydantic_ai
        return LibStatus(name, True, _ver("pydantic-ai"), client=pydantic_ai)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 12. Groq ─────────────────────────────────────────────────────────
async def _init_groq() -> LibStatus:
    name = "groq"
    key  = os.environ.get("GROQ_API_KEY", "")
    try:
        from groq import AsyncGroq
        if not key:
            return LibStatus(name, False, notes="GROQ_API_KEY not set")
        client = AsyncGroq(api_key=key)
        return LibStatus(name, True, _ver("groq"), "async client ready", client=client)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 13. Google GenAI ─────────────────────────────────────────────────
async def _init_google_genai() -> LibStatus:
    name = "google_genai"
    key  = os.environ.get("GOOGLE_API_KEY", "") or os.environ.get("GEMINI_API_KEY", "")
    try:
        import google.generativeai as genai
        if not key:
            return LibStatus(name, False, notes="GOOGLE_API_KEY / GEMINI_API_KEY not set")
        genai.configure(api_key=key)
        return LibStatus(name, True, _ver("google-generativeai"), "configured", client=genai)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 14. OpenTelemetry ─────────────────────────────────────────────────
async def _init_opentelemetry() -> LibStatus:
    name = "opentelemetry"
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

        provider = TracerProvider()
        otlp_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")
        if otlp_endpoint:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint)))
            notes = f"OTLP → {otlp_endpoint}"
        else:
            notes = "no OTEL_EXPORTER_OTLP_ENDPOINT set — traces not exported"

        trace.set_tracer_provider(provider)
        tracer = trace.get_tracer("aiss")
        return LibStatus(name, True, _ver("opentelemetry-api"), notes, client=tracer)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 15. Logfire ───────────────────────────────────────────────────────
async def _init_logfire() -> LibStatus:
    name = "logfire"
    token = os.environ.get("LOGFIRE_TOKEN", "")
    try:
        import logfire
        if token:
            logfire.configure(token=token, service_name="aiss")
            return LibStatus(name, True, _ver("logfire"), "token configured", client=logfire)
        else:
            logfire.configure(send_to_logfire=False, service_name="aiss")
            return LibStatus(name, True, _ver("logfire"), "local-only (no LOGFIRE_TOKEN)", client=logfire)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 16. spaCy ─────────────────────────────────────────────────────────
async def _init_spacy() -> LibStatus:
    name = "spacy"
    try:
        import spacy
        model_name = os.environ.get("SPACY_MODEL", "en_core_web_sm")
        loop = asyncio.get_event_loop()
        try:
            nlp = await loop.run_in_executor(None, lambda: spacy.load(model_name))
        except OSError:
            # Model not downloaded — download it
            logger.info(f"[lib_registry] spaCy: downloading {model_name}...")
            import subprocess
            await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    [sys.executable, "-m", "spacy", "download", model_name],
                    capture_output=True
                )
            )
            nlp = await loop.run_in_executor(None, lambda: spacy.load(model_name))
        return LibStatus(name, True, _ver("spacy"), f"model={model_name}", client=nlp)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 17. Transformers (HuggingFace) ───────────────────────────────────
async def _init_transformers() -> LibStatus:
    name = "transformers"
    try:
        from transformers import pipeline, AutoTokenizer
        import torch
        device = "cuda" if torch.cuda.is_available() else "cpu"
        # Load a small text-classification pipeline for threat classification
        model_id   = os.environ.get("HF_CLASSIFIER_MODEL", "distilbert-base-uncased-finetuned-sst-2-english")
        loop       = asyncio.get_event_loop()
        classifier = await loop.run_in_executor(
            None,
            lambda: pipeline("text-classification", model=model_id,
                             device=0 if device == "cuda" else -1,
                             model_kwargs={"cache_dir": str(MODELS_DIR)})
        )
        notes = f"device={device} model={model_id}"
        return LibStatus(name, True, _ver("transformers"), notes, client=classifier)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 18. scikit-learn ─────────────────────────────────────────────────
async def _init_sklearn() -> LibStatus:
    name = "sklearn"
    try:
        import sklearn
        from sklearn.ensemble import IsolationForest
        # Build a tiny baseline model to verify it works
        import numpy as np
        iso = IsolationForest(n_estimators=10, random_state=42)
        iso.fit(np.random.rand(20, 4))
        return LibStatus(name, True, _ver("scikit-learn"), "IsolationForest ready", client=iso)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 19. River (online ML) ────────────────────────────────────────────
async def _init_river() -> LibStatus:
    name = "river"
    try:
        from river import anomaly, preprocessing
        model = preprocessing.StandardScaler() | anomaly.HalfSpaceTrees(seed=42)
        return LibStatus(name, True, _ver("river"), "online anomaly detector ready", client=model)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 20. YARA ─────────────────────────────────────────────────────────
async def _init_yara() -> LibStatus:
    name = "yara"
    try:
        import yara
        rules_dir = Path("rules")
        compiled  = {}
        if rules_dir.exists():
            for yar in rules_dir.glob("*.yar"):
                try:
                    compiled[yar.stem] = yara.compile(filepath=str(yar))
                except Exception as ye:
                    logger.warning(f"[lib_registry] YARA compile error {yar.name}: {ye}")
        return LibStatus(name, True, _ver("yara-python"),
                         f"{len(compiled)} rule files loaded", client=compiled)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 21. Shodan SDK ────────────────────────────────────────────────────
async def _init_shodan() -> LibStatus:
    name = "shodan"
    key  = os.environ.get("SHODAN_API_KEY", "")
    try:
        import shodan
        if not key:
            return LibStatus(name, False, notes="SHODAN_API_KEY not set")
        api = shodan.Shodan(key)
        return LibStatus(name, True, _ver("shodan"), "API client ready", client=api)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 22. Censys ────────────────────────────────────────────────────────
async def _init_censys() -> LibStatus:
    name = "censys"
    api_id  = os.environ.get("CENSYS_API_ID", "")
    api_sec = os.environ.get("CENSYS_API_SECRET", "")
    try:
        from censys.search import CensysHosts
        if not api_id or not api_sec:
            return LibStatus(name, False, notes="CENSYS_API_ID / CENSYS_API_SECRET not set")
        client = CensysHosts(api_id=api_id, api_secret=api_sec)
        return LibStatus(name, True, _ver("censys"), "hosts search ready", client=client)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 23. IOC Finder ────────────────────────────────────────────────────
async def _init_ioc_finder() -> LibStatus:
    name = "ioc_finder"
    try:
        import ioc_finder
        sample = ioc_finder.find_iocs("Test 8.8.8.8 and CVE-2024-1234")
        return LibStatus(name, True, _ver("ioc-finder"), "IOC extraction ready", client=ioc_finder)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 24. pySigma ───────────────────────────────────────────────────────
async def _init_sigma() -> LibStatus:
    name = "sigma"
    try:
        from sigma.collection import SigmaCollection
        rules_file = Path("rules/sigma_rules.yml")
        if rules_file.exists():
            loop = asyncio.get_event_loop()
            col  = await loop.run_in_executor(
                None, lambda: SigmaCollection.from_yaml(rules_file.read_text())
            )
            count = len(col)
        else:
            count = 0
        return LibStatus(name, True, _ver("pySigma"), f"{count} sigma rule(s) loaded", client=None)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 25. PyATT&CK ─────────────────────────────────────────────────────
async def _init_pyattck() -> LibStatus:
    name = "pyattck"
    try:
        from pyattck import Attck
        loop    = asyncio.get_event_loop()
        attck   = await loop.run_in_executor(None, lambda: Attck(nested_techniques=True))
        return LibStatus(name, True, _ver("pyattck"), "ATT&CK framework loaded", client=attck)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 26. VirusTotal (vt-py) ───────────────────────────────────────────
async def _init_vt() -> LibStatus:
    name = "vt_py"
    key  = os.environ.get("VIRUSTOTAL_API_KEY", "")
    try:
        import vt
        if not key:
            return LibStatus(name, False, notes="VIRUSTOTAL_API_KEY not set")
        client = vt.Client(key)
        return LibStatus(name, True, _ver("vt-py"), "VT async client ready", client=client)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 27. Redis ─────────────────────────────────────────────────────────
async def _init_redis() -> LibStatus:
    name = "redis"
    url  = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
    try:
        import redis.asyncio as aioredis
        client = aioredis.from_url(url, socket_connect_timeout=3, socket_timeout=3)
        await asyncio.wait_for(client.ping(), timeout=3)
        return LibStatus(name, True, _ver("redis"), f"connected: {url}", client=client)
    except Exception as e:
        return LibStatus(name, False, notes=f"Redis unavailable: {e}")


# ── 28. Playwright ────────────────────────────────────────────────────
async def _init_playwright() -> LibStatus:
    name = "playwright"
    try:
        from playwright.async_api import async_playwright
        # Just verify the module imports; don't launch a browser at startup
        return LibStatus(name, True, _ver("playwright"),
                         "phishing screenshot engine ready (lazy launch)", client=async_playwright)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 29. EasyOCR ───────────────────────────────────────────────────────
async def _init_easyocr() -> LibStatus:
    name = "easyocr"
    try:
        import easyocr
        loop   = asyncio.get_event_loop()
        reader = await loop.run_in_executor(
            None,
            lambda: easyocr.Reader(
                ["en"],
                model_storage_directory=str(MODELS_DIR),
                gpu=False,
                verbose=False,
            )
        )
        return LibStatus(name, True, _ver("easyocr"), "English OCR ready", client=reader)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 30. OpenCV ────────────────────────────────────────────────────────
async def _init_opencv() -> LibStatus:
    name = "opencv"
    try:
        import cv2
        return LibStatus(name, True, cv2.__version__, "image processing ready", client=cv2)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 31. OLE Tools (Office malware analysis) ──────────────────────────
async def _init_oletools() -> LibStatus:
    name = "oletools"
    try:
        import oletools.olevba
        import oletools.mraptor
        return LibStatus(name, True, _ver("oletools"), "VBA macro + mraptor analysis ready", client=oletools)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 32. pefile (PE analysis) ─────────────────────────────────────────
async def _init_pefile() -> LibStatus:
    name = "pefile"
    try:
        import pefile
        return LibStatus(name, True, _ver("pefile"), "PE executable analysis ready", client=pefile)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 33. python-magic ─────────────────────────────────────────────────
async def _init_magic() -> LibStatus:
    name = "magic"
    try:
        import magic
        m = magic.Magic(mime=True)
        return LibStatus(name, True, _ver("python-magic"), "MIME-type detection ready", client=m)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 34. docling (document intelligence) ──────────────────────────────
async def _init_docling() -> LibStatus:
    name = "docling"
    try:
        from docling.document_converter import DocumentConverter
        return LibStatus(name, True, _ver("docling"), "document converter ready", client=DocumentConverter)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 35. PyMuPDF ───────────────────────────────────────────────────────
async def _init_pymupdf() -> LibStatus:
    name = "pymupdf"
    try:
        import pymupdf as fitz
        return LibStatus(name, True, _ver("pymupdf"), "PDF forensics ready", client=fitz)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 36. Boto3 (AWS) ──────────────────────────────────────────────────
async def _init_boto3() -> LibStatus:
    name = "boto3"
    key  = os.environ.get("AWS_ACCESS_KEY_ID", "")
    sec  = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
    try:
        import boto3
        if not key or not sec:
            return LibStatus(name, False, notes="AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY not set")
        session = boto3.Session(
            aws_access_key_id=key,
            aws_secret_access_key=sec,
            region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        )
        return LibStatus(name, True, _ver("boto3"), "AWS session ready", client=session)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 37. Azure Identity + Storage ─────────────────────────────────────
async def _init_azure() -> LibStatus:
    name = "azure"
    conn = os.environ.get("AZURE_STORAGE_CONNECTION_STRING", "")
    try:
        from azure.storage.blob import BlobServiceClient
        if not conn:
            return LibStatus(name, False, notes="AZURE_STORAGE_CONNECTION_STRING not set")
        client = BlobServiceClient.from_connection_string(conn)
        return LibStatus(name, True, _ver("azure-storage-blob"), "Blob storage ready", client=client)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 38. Kubernetes ────────────────────────────────────────────────────
async def _init_kubernetes() -> LibStatus:
    name = "kubernetes"
    try:
        from kubernetes import client as k8s_client, config as k8s_config
        try:
            k8s_config.load_incluster_config()
            notes = "in-cluster config"
        except Exception:
            try:
                k8s_config.load_kube_config()
                notes = "kubeconfig loaded"
            except Exception:
                return LibStatus(name, False, notes="no in-cluster or kubeconfig found")
        v1 = k8s_client.CoreV1Api()
        return LibStatus(name, True, _ver("kubernetes"), notes, client=v1)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 39. pyttsx3 (TTS) ────────────────────────────────────────────────
async def _init_tts() -> LibStatus:
    name = "tts"
    if os.environ.get("DISABLE_TTS", "").lower() in ("1", "true"):
        return LibStatus(name, False, notes="DISABLE_TTS=true")
    try:
        import pyttsx3
        loop   = asyncio.get_event_loop()
        engine = await loop.run_in_executor(None, pyttsx3.init)
        return LibStatus(name, True, _ver("pyttsx3"), "voice alert engine ready", client=engine)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 40. Polars ────────────────────────────────────────────────────────
async def _init_polars() -> LibStatus:
    name = "polars"
    try:
        import polars as pl
        # smoke test
        df = pl.DataFrame({"a": [1, 2, 3]})
        return LibStatus(name, True, _ver("polars"), "fast DataFrame engine ready", client=pl)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 41. Numba (JIT) ───────────────────────────────────────────────────
async def _init_numba() -> LibStatus:
    name = "numba"
    try:
        from numba import njit
        import numpy as np

        @njit
        def _warmup(x):
            s = 0.0
            for v in x:
                s += v
            return s

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: _warmup(np.array([1.0, 2.0, 3.0])))
        return LibStatus(name, True, _ver("numba"), "JIT compiler warmed up", client=njit)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 42. Semantic Kernel ───────────────────────────────────────────────
async def _init_semantic_kernel() -> LibStatus:
    name = "semantic_kernel"
    key  = os.environ.get("OPENAI_API_KEY", "") or os.environ.get("ANTHROPIC_API_KEY", "")
    try:
        import semantic_kernel as sk
        if not key:
            return LibStatus(name, False, notes="no OPENAI_API_KEY or ANTHROPIC_API_KEY set")
        return LibStatus(name, True, _ver("semantic-kernel"), "SK kernel ready", client=sk)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 43. DuckDuckGo Search ─────────────────────────────────────────────
async def _init_ddgs() -> LibStatus:
    name = "ddgs"
    try:
        from duckduckgo_search import DDGS
        return LibStatus(name, True, _ver("duckduckgo_search"),
                         "web search (no API key needed)", client=DDGS)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 44. Wikipedia ─────────────────────────────────────────────────────
async def _init_wikipedia() -> LibStatus:
    name = "wikipedia"
    try:
        import wikipedia
        return LibStatus(name, True, _ver("wikipedia"), "knowledge base lookup ready", client=wikipedia)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 45. Scapy ─────────────────────────────────────────────────────────
async def _init_scapy() -> LibStatus:
    name = "scapy"
    try:
        from scapy.all import IP, TCP
        return LibStatus(name, True, _ver("scapy"), "packet crafting ready", client=None)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 46. Ultralytics (YOLO vision) ────────────────────────────────────
async def _init_ultralytics() -> LibStatus:
    name = "ultralytics"
    if os.environ.get("DISABLE_YOLO", "1") == "1":
        return LibStatus(name, False, notes="DISABLE_YOLO=1 (set to 0 to enable)")
    try:
        from ultralytics import YOLO
        return LibStatus(name, True, _ver("ultralytics"), "YOLO vision model ready (lazy load)", client=YOLO)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 47. Langfuse (LLM observability) ────────────────────────────────
async def _init_langfuse() -> LibStatus:
    name = "langfuse"
    pk   = os.environ.get("LANGFUSE_PUBLIC_KEY", "")
    sk   = os.environ.get("LANGFUSE_SECRET_KEY", "")
    try:
        from langfuse import Langfuse
        if not pk or not sk:
            return LibStatus(name, False, notes="LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY not set")
        client = Langfuse(public_key=pk, secret_key=sk,
                          host=os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com"))
        return LibStatus(name, True, _ver("langfuse"), "LLM tracing active", client=client)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 48. Ragas (RAG eval) ─────────────────────────────────────────────
async def _init_ragas() -> LibStatus:
    name = "ragas"
    try:
        import ragas
        return LibStatus(name, True, _ver("ragas"), "RAG evaluation ready", client=ragas)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 49. APScheduler (already used — just verify) ─────────────────────
async def _init_apscheduler() -> LibStatus:
    name = "apscheduler"
    try:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        return LibStatus(name, True, _ver("APScheduler"), "async job scheduler ready", client=AsyncIOScheduler)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 50. netifaces2 ───────────────────────────────────────────────────
async def _init_netifaces() -> LibStatus:
    name = "netifaces"
    try:
        import netifaces2 as netifaces
        ifaces = netifaces.interfaces()
        return LibStatus(name, True, _ver("netifaces2"),
                         f"{len(ifaces)} interfaces: {ifaces[:4]}", client=netifaces)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 51. ioc_fanger (IOC defanging/refanging) ─────────────────────────
async def _init_ioc_fanger() -> LibStatus:
    name = "ioc_fanger"
    try:
        import ioc_fanger
        # smoke-test: refang a defanged IP
        result = ioc_fanger.refang("1[.]2[.]3[.]4")
        assert result == "1.2.3.4"
        return LibStatus(name, True, _ver("ioc-fanger"),
                         "IOC fang/defang ready", client=ioc_fanger)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 52. Kombu (message broker abstraction for Celery) ────────────────
async def _init_kombu() -> LibStatus:
    name = "kombu"
    try:
        from kombu import Connection
        url = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
        # Just verify the module loads; actual connection tested by redis init
        return LibStatus(name, True, _ver("kombu"),
                         f"broker={url.split('@')[-1][:30]}", client=Connection)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 53. LangSmith (LangChain tracing) ───────────────────────────────
async def _init_langsmith() -> LibStatus:
    name = "langsmith"
    key  = os.environ.get("LANGCHAIN_API_KEY", "") or os.environ.get("LANGSMITH_API_KEY", "")
    try:
        import langsmith
        if not key:
            return LibStatus(name, False, notes="LANGCHAIN_API_KEY / LANGSMITH_API_KEY not set")
        os.environ.setdefault("LANGCHAIN_TRACING_V2", "true")
        os.environ.setdefault("LANGCHAIN_API_KEY", key)
        return LibStatus(name, True, _ver("langsmith"), "LangChain tracing enabled", client=langsmith)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 54. Accelerate (HuggingFace distributed/mixed-precision) ────────
async def _init_accelerate() -> LibStatus:
    name = "accelerate"
    try:
        from accelerate import Accelerator
        acc = Accelerator()
        return LibStatus(name, True, _ver("accelerate"),
                         f"device={acc.device}", client=acc)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 55. Optimum (HuggingFace model optimisation) ────────────────────
async def _init_optimum() -> LibStatus:
    name = "optimum"
    try:
        import optimum
        return LibStatus(name, True, _ver("optimum"),
                         "ONNX/quantisation optimisation ready", client=optimum)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 56. Altair (declarative visualisation) ──────────────────────────
async def _init_altair() -> LibStatus:
    name = "altair"
    try:
        import altair as alt
        return LibStatus(name, True, _ver("altair"),
                         "declarative chart library ready", client=alt)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 57. Guardrails-AI ────────────────────────────────────────────────
async def _init_guardrails() -> LibStatus:
    name = "guardrails"
    try:
        import guardrails
        return LibStatus(name, True, _ver("guardrails-ai"),
                         "LLM output validation ready", client=guardrails)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 58. Authlib ──────────────────────────────────────────────────────
async def _init_authlib() -> LibStatus:
    name = "authlib"
    try:
        from authlib.integrations.httpx_client import AsyncOAuth2Client
        configured = []
        for p in ["GOOGLE_OAUTH_CLIENT_ID", "GITHUB_OAUTH_CLIENT_ID", "MICROSOFT_OAUTH_CLIENT_ID"]:
            if os.environ.get(p):
                configured.append(p.split("_")[0].lower())
        notes = f"providers: {configured}" if configured else "no OAuth providers configured"
        return LibStatus(name, True, _ver("Authlib"), notes, client=AsyncOAuth2Client)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 59. tiktoken ─────────────────────────────────────────────────────
async def _init_tiktoken() -> LibStatus:
    name = "tiktoken"
    try:
        import tiktoken
        enc = tiktoken.get_encoding("cl100k_base")
        n   = len(enc.encode("Hello AISS token counter"))
        return LibStatus(name, True, _ver("tiktoken"),
                         f"cl100k_base ready (test={n} tokens)", client=enc)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 60. OpenAI SDK ────────────────────────────────────────────────────
async def _init_openai_sdk() -> LibStatus:
    name = "openai_sdk"
    key  = os.environ.get("OPENAI_API_KEY", "")
    try:
        from openai import AsyncOpenAI
        if not key:
            return LibStatus(name, False, notes="OPENAI_API_KEY not set")
        client = AsyncOpenAI(api_key=key)
        return LibStatus(name, True, _ver("openai"),
                         "AsyncOpenAI client ready", client=client)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ── 61. llama_cpp_python (local LLM) ─────────────────────────────────
async def _init_llama_cpp() -> LibStatus:
    name = "llama_cpp"
    model_path = os.environ.get("LLAMA_MODEL_PATH", "")
    try:
        from llama_cpp import Llama
        if not model_path or not Path(model_path).exists():
            return LibStatus(name, False,
                             notes=f"LLAMA_MODEL_PATH not set or file missing: {model_path or '(empty)'}")
        loop  = asyncio.get_event_loop()
        model = await loop.run_in_executor(
            None,
            lambda: Llama(model_path=model_path, n_ctx=2048, verbose=False)
        )
        return LibStatus(name, True, _ver("llama-cpp-python"), f"loaded: {model_path}", client=model)
    except Exception as e:
        return LibStatus(name, False, notes=str(e))


# ─────────────────────────────────────────────────────────────────────
# LibRegistry — orchestrates all initialisers
# ─────────────────────────────────────────────────────────────────────

# Map: display_name → (init_coro_fn, concurrency_group)
# Groups: "heavy" = may download models (runs sequentially)
#         "light" = fast SDK setup (runs concurrently)
_INITIALISERS: list[tuple] = [
    # name,               fn,                        group
    ("sentence_transformers", _init_sentence_transformers, "heavy"),
    ("faiss",                 _init_faiss,                 "light"),
    ("chromadb",              _init_chromadb,              "heavy"),
    ("lancedb",               _init_lancedb,               "light"),
    ("qdrant",                _init_qdrant,                "light"),
    ("langchain",             _init_langchain,             "light"),
    ("langgraph",             _init_langgraph,             "light"),
    ("crewai",                _init_crewai,                "light"),
    ("litellm",               _init_litellm,               "light"),
    ("instructor",            _init_instructor,            "light"),
    ("pydantic_ai",           _init_pydantic_ai,           "light"),
    ("groq",                  _init_groq,                  "light"),
    ("google_genai",          _init_google_genai,          "light"),
    ("opentelemetry",         _init_opentelemetry,         "light"),
    ("logfire",               _init_logfire,               "light"),
    ("spacy",                 _init_spacy,                 "heavy"),
    ("transformers",          _init_transformers,          "heavy"),
    ("sklearn",               _init_sklearn,               "light"),
    ("river",                 _init_river,                 "light"),
    ("yara",                  _init_yara,                  "light"),
    ("shodan",                _init_shodan,                "light"),
    ("censys",                _init_censys,                "light"),
    ("ioc_finder",            _init_ioc_finder,            "light"),
    ("sigma",                 _init_sigma,                 "light"),
    ("pyattck",               _init_pyattck,               "heavy"),
    ("vt_py",                 _init_vt,                    "light"),
    ("redis",                 _init_redis,                 "light"),
    ("playwright",            _init_playwright,            "light"),
    ("easyocr",               _init_easyocr,               "heavy"),
    ("opencv",                _init_opencv,                "light"),
    ("oletools",              _init_oletools,              "light"),
    ("pefile",                _init_pefile,                "light"),
    ("magic",                 _init_magic,                 "light"),
    ("docling",               _init_docling,               "light"),
    ("pymupdf",               _init_pymupdf,               "light"),
    ("boto3",                 _init_boto3,                 "light"),
    ("azure",                 _init_azure,                 "light"),
    ("kubernetes",            _init_kubernetes,            "light"),
    ("tts",                   _init_tts,                   "light"),
    ("polars",                _init_polars,                "light"),
    ("numba",                 _init_numba,                 "heavy"),
    ("semantic_kernel",       _init_semantic_kernel,       "light"),
    ("ddgs",                  _init_ddgs,                  "light"),
    ("wikipedia",             _init_wikipedia,             "light"),
    ("scapy",                 _init_scapy,                 "light"),
    ("ultralytics",           _init_ultralytics,           "light"),
    ("langfuse",              _init_langfuse,              "light"),
    ("ragas",                 _init_ragas,                 "light"),
    ("apscheduler",           _init_apscheduler,           "light"),
    ("llama_cpp",             _init_llama_cpp,             "heavy"),
    # New integrations
    ("netifaces",             _init_netifaces,             "light"),
    ("ioc_fanger",            _init_ioc_fanger,            "light"),
    ("kombu",                 _init_kombu,                 "light"),
    ("langsmith",             _init_langsmith,             "light"),
    ("accelerate",            _init_accelerate,            "heavy"),
    ("optimum",               _init_optimum,               "light"),
    ("altair",                _init_altair,                "light"),
    ("guardrails",            _init_guardrails,            "light"),
    ("authlib",               _init_authlib,               "light"),
    ("tiktoken",              _init_tiktoken,              "light"),
    ("openai_sdk",            _init_openai_sdk,            "light"),
]


class LibRegistry:
    """
    Central registry for all optional library integrations.

    Usage:
        registry = LibRegistry()
        await registry.init_all()          # run once at startup

        registry.is_enabled("chromadb")    # bool
        registry.get("chromadb")           # client or None
        registry.status()                  # list[dict] — API-safe
        registry.summary()                 # one-line startup log
    """

    def __init__(self) -> None:
        self._results: dict[str, LibStatus] = {}

    async def init_all(self, *, timeout_secs: float = 120.0) -> None:
        """
        Run all initialisers.
        Light initialisers run concurrently; heavy ones (model downloads) run
        sequentially to avoid OOM during parallel downloads.
        """
        t0 = time.time()
        logger.info("🔍 LibRegistry: starting library integration scan...")

        light  = [(n, fn) for n, fn, g in _INITIALISERS if g == "light"]
        heavy  = [(n, fn) for n, fn, g in _INITIALISERS if g == "heavy"]

        # ── Run light initialisers concurrently ───────────────────────
        async def _run_one(name: str, fn) -> LibStatus:
            try:
                return await asyncio.wait_for(fn(), timeout=30.0)
            except asyncio.TimeoutError:
                return LibStatus(name, False, notes="timeout (>30s)")
            except Exception as e:
                return LibStatus(name, False, notes=str(e))

        light_statuses = await asyncio.gather(*[_run_one(n, fn) for n, fn in light])
        for st in light_statuses:
            self._results[st.name] = st

        # ── Run heavy initialisers sequentially ───────────────────────
        for name, fn in heavy:
            try:
                st = await asyncio.wait_for(fn(), timeout=timeout_secs)
            except asyncio.TimeoutError:
                st = LibStatus(name, False, notes=f"timeout (>{timeout_secs}s)")
            except Exception as e:
                st = LibStatus(name, False, notes=str(e))
            self._results[st.name] = st

        elapsed = time.time() - t0
        enabled = sum(1 for s in self._results.values() if s.enabled)
        disabled = len(self._results) - enabled
        logger.info(
            f"✅ LibRegistry: {enabled} enabled, {disabled} disabled "
            f"({elapsed:.1f}s) — use GET /api/system/libraries for details"
        )

    def is_enabled(self, name: str) -> bool:
        return self._results.get(name, LibStatus(name, False)).enabled

    def get(self, name: str) -> Optional[Any]:
        st = self._results.get(name)
        return st.client if st and st.enabled else None

    def status(self) -> list[dict]:
        return [s.to_dict() for s in sorted(self._results.values(), key=lambda x: x.name)]

    def summary(self) -> str:
        enabled  = [n for n, s in self._results.items() if s.enabled]
        disabled = [n for n, s in self._results.items() if not s.enabled]
        return (
            f"LibRegistry: ✅ {len(enabled)} enabled | "
            f"⚠ {len(disabled)} disabled\n"
            f"  Enabled : {', '.join(sorted(enabled)) or 'none'}\n"
            f"  Disabled: {', '.join(sorted(disabled)) or 'none'}"
        )


# ─────────────────────────────────────────────────────────────────────
# Module-level singleton — imported everywhere
# ─────────────────────────────────────────────────────────────────────
lib_registry = LibRegistry()
