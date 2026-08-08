from fastapi import APIRouter, Depends
from modules.dataset_loader import dataset_loader
from core.auth import get_current_user

router = APIRouter()


@router.post("/load-all")
async def load_all_datasets(current_user: dict = Depends(get_current_user)):
    result = dataset_loader.load_all_datasets()
    return result


@router.get("/patterns")
async def get_patterns(current_user: dict = Depends(get_current_user)):
    patterns = dataset_loader.get_patterns()
    return patterns


@router.get("/status")
async def dataset_status(current_user: dict = Depends(get_current_user)):
    return {
        "total_rows_processed": dataset_loader.patterns.get("total_rows_processed", 0),
        "loaded_at": dataset_loader.patterns.get("loaded_at"),
        "datasets": ["network_intrusion", "malware_detection", "phishing_urls"]
    }
