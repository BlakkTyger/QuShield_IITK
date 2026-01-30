"""Rating Schemas"""

from typing import List, Optional
from pydantic import BaseModel


class EnterpriseRating(BaseModel):
    """Schema for enterprise rating response."""
    enterprise_score: int
    max_score: int = 1000
    category: str  # Legacy, Standard, Elite
    tier_thresholds: dict = {
        "Legacy": {"min": 0, "max": 399},
        "Standard": {"min": 400, "max": 699},
        "Elite": {"min": 700, "max": 1000},
    }
    breakdown: Optional[dict] = None


class AssetRatingItem(BaseModel):
    """Schema for individual asset rating."""
    id: str
    fqdn: str
    url: str
    score: int
    max_score: int = 1000
    category: str
    hndl_score: Optional[float]
    quantum_safety: Optional[str]


class AssetRating(BaseModel):
    """Schema for asset ratings response."""
    items: List[AssetRatingItem]
    total: int
    average_score: float
