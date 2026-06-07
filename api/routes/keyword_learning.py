from fastapi import APIRouter, Depends
from pydantic import BaseModel
from modules.keyword_learner import keyword_learner
from auth.dependencies import get_current_user

router = APIRouter()


class LearnRequest(BaseModel):
    youtube_url: str


@router.post("/")
async def learn_from_video(
    request: LearnRequest,
    current_user: dict = Depends(get_current_user),
):
    result = keyword_learner.learn_from_youtube(request.youtube_url)
    return result


@router.get("/stats")
async def get_stats(
    current_user: dict = Depends(get_current_user),
):
    return {
        "total_sources_learned": keyword_learner.patterns.get("total_sources", 0),
        "total_patterns_extracted": keyword_learner.total_extracted,
        "known_malware":     len(keyword_learner.patterns.get("malware_names", [])),
        "known_techniques":  len(keyword_learner.patterns.get("attack_techniques", [])),
        "known_cves":        len(keyword_learner.patterns.get("cve_numbers", [])),
        "known_tools":       len(keyword_learner.patterns.get("tools", [])),
        "last_updated":      keyword_learner.patterns.get("last_updated"),
        "status":            "active",
    }


@router.get("/patterns")
async def get_all_patterns(
    current_user: dict = Depends(get_current_user),
):
    return keyword_learner.patterns


@router.post("/test-url")
async def test_url(
    request: LearnRequest,
    current_user: dict = Depends(get_current_user),
):
    try:
        video_id = keyword_learner.extract_video_id(request.youtube_url)
        return {"valid": True, "video_id": video_id}
    except ValueError as e:
        return {"valid": False, "error": str(e)}
