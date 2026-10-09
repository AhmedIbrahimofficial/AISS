"""AISS - Semantic Threat Store
Vector-based threat intelligence store using sentence-transformers + ChromaDB.

Features:
  - Embed and persist every threat as a vector
  - Semantic similarity search: "find threats similar to ransomware C2 traffic"
  - Deduplication via cosine similarity (skip if > 0.92 similar threat exists)
  - Powered by ChromaDB (persistent) + sentence-transformers embeddings
  - Gracefully disabled if either library is unavailable

Usage:
    from modules.semantic_threat_store import semantic_store
    await semantic_store.add_threat(threat_dict)
    results = await semantic_store.search("port scan followed by C2", n=5)
"""
import asyncio
from typing import Optional
from utils.logger import setup_logger

logger = setup_logger("semantic_threat_store")

_COLLECTION_NAME = "threats"
_SIMILARITY_THRESHOLD = 0.92   # skip if cosine similarity > this


class SemanticThreatStore:
    def __init__(self):
        self._ready    = False
        self._chroma   = None   # chromadb PersistentClient
        self._sbert    = None   # SentenceTransformer model
        self._col      = None   # chroma Collection

    def _ensure_ready(self) -> bool:
        if self._ready:
            return True
        try:
            from core.lib_registry import lib_registry
            self._chroma = lib_registry.get("chromadb")
            self._sbert  = lib_registry.get("sentence_transformers")
            if not self._chroma or not self._sbert:
                return False
            self._col   = self._chroma.get_or_create_collection(_COLLECTION_NAME)
            self._ready = True
            return True
        except Exception as e:
            logger.debug(f"SemanticThreatStore not ready: {e}")
            return False

    def _embed(self, text: str) -> list[float]:
        vec = self._sbert.encode([text])
        return vec[0].tolist()

    async def add_threat(self, threat: dict) -> bool:
        """
        Embed and store a threat. Skips if a semantically similar threat
        already exists (cosine similarity > threshold).
        Returns True if added, False if skipped/unavailable.
        """
        if not self._ensure_ready():
            return False
        loop = asyncio.get_event_loop()
        try:
            tid  = threat.get("id", "")[:36]
            text = (
                f"{threat.get('type','')} {threat.get('description','')} "
                f"{threat.get('source','')} {threat.get('severity','')}"
            )
            vec = await loop.run_in_executor(None, lambda: self._embed(text))

            # Near-duplicate check
            existing = await loop.run_in_executor(
                None,
                lambda: self._col.query(query_embeddings=[vec], n_results=1,
                                        include=["distances"])
            )
            if existing["distances"] and existing["distances"][0]:
                dist = existing["distances"][0][0]
                # ChromaDB returns L2 distance; convert: sim ≈ 1 - dist/2
                sim = max(0.0, 1.0 - dist / 2.0)
                if sim > _SIMILARITY_THRESHOLD:
                    logger.debug(f"SemanticStore: skipping near-dup threat {tid[:8]} (sim={sim:.3f})")
                    return False

            meta = {
                "type":     str(threat.get("type",     "")),
                "severity": str(threat.get("severity", "")),
                "source":   str(threat.get("source",   ""))[:200],
                "status":   str(threat.get("status",   "")),
            }
            await loop.run_in_executor(
                None,
                lambda: self._col.add(
                    ids=[tid],
                    embeddings=[vec],
                    documents=[text[:1000]],
                    metadatas=[meta],
                )
            )
            return True
        except Exception as e:
            logger.debug(f"SemanticStore add error: {e}")
            return False

    async def search(self, query: str, n: int = 5,
                     severity_filter: Optional[str] = None) -> list[dict]:
        """
        Semantic search over stored threats.
        Returns list of dicts: {id, document, metadata, score}
        """
        if not self._ensure_ready():
            return []
        loop = asyncio.get_event_loop()
        try:
            vec   = await loop.run_in_executor(None, lambda: self._embed(query))
            where = {"severity": severity_filter} if severity_filter else None
            kwargs = dict(query_embeddings=[vec], n_results=n, include=["documents", "metadatas", "distances"])
            if where:
                kwargs["where"] = where
            res  = await loop.run_in_executor(None, lambda: self._col.query(**kwargs))

            out = []
            ids  = res.get("ids", [[]])[0]
            docs = res.get("documents", [[]])[0]
            metas= res.get("metadatas", [[]])[0]
            dists= res.get("distances", [[]])[0]
            for tid, doc, meta, dist in zip(ids, docs, metas, dists):
                out.append({
                    "id":       tid,
                    "document": doc,
                    "metadata": meta,
                    "score":    round(max(0.0, 1.0 - dist / 2.0), 4),
                })
            return out
        except Exception as e:
            logger.debug(f"SemanticStore search error: {e}")
            return []

    async def count(self) -> int:
        if not self._ensure_ready():
            return 0
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, lambda: self._col.count())
        except Exception:
            return 0

    def is_available(self) -> bool:
        return self._ensure_ready()


# Module-level singleton
semantic_store = SemanticThreatStore()
