from fastapi import APIRouter, Depends
from pydantic import BaseModel
from modules.self_learner import self_learner
from auth.dependencies import get_current_user

router = APIRouter()


class LearnRequest(BaseModel):
    youtube_url: str


class LearnResponse(BaseModel):
    status: str
    video_url: str
    video_id: str = None
    knowledge: dict = None
    total_learned: int = 0
    error: str = None


@router.post("/", response_model=LearnResponse)
async def learn_from_video(
    request: LearnRequest,
    current_user: dict = Depends(get_current_user),
):
    result = await self_learner.learn_from_youtube(request.youtube_url)
    return result


@router.get("/stats")
async def get_learning_stats(
    current_user: dict = Depends(get_current_user),
):
    return {
        "total_videos_learned": self_learner.learned_count,
        "status": "active",
        "system": "AISS Self-Learning Engine",
    }


@router.post("/test-url")
async def test_youtube_url(
    request: LearnRequest,
    current_user: dict = Depends(get_current_user),
):
    try:
        video_id = self_learner.extract_video_id(request.youtube_url)
        return {
            "valid":       True,
            "video_id":    video_id,
            "youtube_url": request.youtube_url,
        }
    except ValueError as e:
        return {
            "valid": False,
            "error": str(e),
        }
