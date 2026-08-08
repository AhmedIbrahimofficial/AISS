"""AISS - Document & File Intelligence Analyzer
Deep analysis of uploaded files for malware, macros, exploits, and IOCs.

Capabilities (gracefully disabled when library is absent):
  - PDF  : pymupdf (text/image extraction), pdfplumber (tables)
  - Office: oletools (VBA macro detection), msoffcrypto (encrypted docs)
  - PE   : pefile (PE header analysis, import table, section entropy)
  - Magic: python-magic (true file type by bytes — defeats extension spoofing)
  - OCR  : easyocr (extract text from image-based documents)
  - Docling: structured content extraction from PDFs, DOCX, PPTX, HTML
  - IOC  : ioc_extractor (pull IPs, hashes, CVEs from document text)

Usage:
    from modules.document_analyzer import document_analyzer
    result = await document_analyzer.analyze("/path/to/file.pdf")
"""
import asyncio
import math
import os
import collections
from pathlib import Path
from typing import Optional
from utils.logger import setup_logger

logger = setup_logger("document_analyzer")


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq  = collections.Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


class DocumentAnalyzer:
    def __init__(self):
        self._magic    = None
        self._pefile   = None
        self._oletools = None
        self._fitz     = None
        self._easyocr  = None
        self._docling  = None
        self._tried    = False

    def _lazy_init(self):
        if self._tried:
            return
        self._tried = True
        try:
            from core.lib_registry import lib_registry
            if lib_registry.is_enabled("magic"):
                self._magic = lib_registry.get("magic")
            if lib_registry.is_enabled("pefile"):
                import pefile
                self._pefile = pefile
            if lib_registry.is_enabled("oletools"):
                import oletools.olevba as olevba
                import oletools.mraptor as mraptor
                self._oletools = (olevba, mraptor)
            if lib_registry.is_enabled("pymupdf"):
                self._fitz = lib_registry.get("pymupdf")
            if lib_registry.is_enabled("easyocr"):
                self._easyocr = lib_registry.get("easyocr")
            if lib_registry.is_enabled("docling"):
                self._docling = lib_registry.get("docling")
        except Exception as e:
            logger.debug(f"DocumentAnalyzer lazy init: {e}")

    async def analyze(self, filepath: str) -> dict:
        """
        Full file analysis. Returns structured threat-relevant result.
        """
        self._lazy_init()
        loop   = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, lambda: self._analyze_sync(filepath))
        return result

    def _analyze_sync(self, filepath: str) -> dict:
        path = Path(filepath)
        if not path.exists():
            return {"error": "file not found", "path": filepath}

        out: dict = {
            "path":       filepath,
            "size_bytes": path.stat().st_size,
            "mime_type":  "",
            "file_type":  "",
            "entropy":    0.0,
            "threats":    [],
            "iocs":       {},
            "macros":     None,
            "pe_info":    None,
            "text":       "",
        }

        # Read raw bytes
        try:
            raw = path.read_bytes()
        except Exception as e:
            out["error"] = str(e)
            return out

        # Entropy
        out["entropy"] = round(_entropy(raw[:65536]), 4)
        if out["entropy"] > 7.2:
            out["threats"].append({
                "type": "high_entropy",
                "detail": f"entropy={out['entropy']:.2f} — likely packed/encrypted"
            })

        # MIME type via magic
        if self._magic:
            try:
                out["mime_type"] = self._magic.from_buffer(raw[:4096])
                out["file_type"] = out["mime_type"]
            except Exception:
                pass

        # PE analysis
        if self._pefile:
            try:
                pe = self._pefile.PE(data=raw)
                imports = []
                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll = entry.dll.decode("utf-8", errors="ignore")
                        imports.append(dll)
                suspicious_dlls = [d for d in imports if any(
                    s in d.lower() for s in ["ws2_32", "wininet", "urlmon", "kernel32"]
                )]
                out["pe_info"] = {
                    "is_pe":          True,
                    "imports":        imports[:20],
                    "suspicious_dlls": suspicious_dlls,
                    "machine":        hex(pe.FILE_HEADER.Machine),
                }
                pe.close()
                if suspicious_dlls:
                    out["threats"].append({
                        "type": "suspicious_pe_imports",
                        "detail": f"imports: {suspicious_dlls}"
                    })
            except Exception:
                pass

        # Office macro analysis
        if self._oletools:
            olevba, mraptor = self._oletools
            try:
                vba_parser = olevba.VBA_Parser(filepath, data=raw)
                if vba_parser.detect_vba_macros():
                    macros = []
                    for (vba_filename, stream_path, vba_code) in vba_parser.extract_all_macros():
                        macros.append({
                            "stream": stream_path,
                            "code":   vba_code[:500],
                        })
                    # mraptor risk classification
                    mrap = mraptor.mraptor(filepath)
                    mrap.run()
                    out["macros"] = {
                        "count":     len(macros),
                        "macros":    macros[:3],
                        "risk":      mrap.result,
                    }
                    if mrap.result in (mraptor.mraptor.RESULT_SUSPICIOUS,
                                       mraptor.mraptor.RESULT_MALICIOUS):
                        out["threats"].append({
                            "type": "malicious_macro",
                            "detail": f"mraptor={mrap.result} macro count={len(macros)}"
                        })
            except Exception as e:
                logger.debug(f"oletools error: {e}")

        # PDF text extraction
        if self._fitz and (out["mime_type"] == "application/pdf"
                           or filepath.lower().endswith(".pdf")):
            try:
                doc = self._fitz.open(filepath)
                pages_text = []
                for page in doc:
                    pages_text.append(page.get_text())
                doc.close()
                out["text"] = " ".join(pages_text)[:5000]
            except Exception as e:
                logger.debug(f"pymupdf error: {e}")

        # docling for structured content
        if self._docling and not out["text"]:
            try:
                converter = self._docling
                result_obj = converter().convert(filepath)
                out["text"] = result_obj.document.export_to_markdown()[:5000]
            except Exception as e:
                logger.debug(f"docling error: {e}")

        # OCR for images
        if self._easyocr and not out["text"] and out["mime_type"] and "image" in out["mime_type"]:
            try:
                results = self._easyocr.readtext(filepath, detail=0)
                out["text"] = " ".join(results)[:3000]
            except Exception as e:
                logger.debug(f"easyocr error: {e}")

        # IOC extraction from text
        if out["text"]:
            try:
                from modules.ioc_extractor import ioc_extractor
                out["iocs"] = ioc_extractor.extract(out["text"])
                if out["iocs"].get("ips") or out["iocs"].get("hashes"):
                    out["threats"].append({
                        "type": "embedded_iocs",
                        "detail": f"IPs: {out['iocs']['ips'][:5]}, "
                                  f"hashes: {out['iocs']['hashes'][:3]}"
                    })
            except Exception as e:
                logger.debug(f"IOC extraction error: {e}")

        return out

    def is_available(self) -> bool:
        self._lazy_init()
        return True   # always works, degrades gracefully


# Singleton
document_analyzer = DocumentAnalyzer()
