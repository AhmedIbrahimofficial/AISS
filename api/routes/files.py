"""CyberSentinel - File Inspector API Routes"""
import os
import sys
import tempfile
from fastapi import APIRouter, UploadFile, File

router = APIRouter()

IS_WINDOWS = sys.platform == "win32"
QUARANTINE_DIR = os.path.join(
    os.environ.get("TEMP", "C:\\Windows\\Temp") if IS_WINDOWS else "/tmp",
    "cybersentinel_quarantine"
)


@router.post("/inspect")
async def inspect_uploaded_file(file: UploadFile = File(...)):
    suffix = os.path.splitext(file.filename)[1] if file.filename else ""
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name
    return {
        "filename": file.filename,
        "size": len(content),
        "path": tmp_path,
        "status": "queued_for_inspection"
    }


@router.get("/quarantine")
async def list_quarantine():
    if not os.path.exists(QUARANTINE_DIR):
        return {"files": [], "count": 0}
    files = os.listdir(QUARANTINE_DIR)
    return {"files": files, "count": len(files)}
