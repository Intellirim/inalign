"""
In-A-Lign Platform API Endpoints.

Main API for the unified security & efficiency platform.
"""

from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
import logging

from app.platform import InALign, PlatformConfig, get_platform, init

logger = logging.getLogger("inalign.api.platform")
router = APIRouter(prefix="/platform", tags=["platform"])


# =============================================================================
# Request/Response Models
# =============================================================================

class ProcessRequest(BaseModel):
    """Request to process user input through the platform."""
    text: str = Field(..., min_length=1, max_length=50000, description="User input text")
    user_id: str = Field(..., min_length=1, max_length=256, description="Unique user identifier")
    ip_address: Optional[str] = Field(None, description="User's IP address")
    system_prompt: Optional[str] = Field(None, description="System prompt for caching")
    force_model: Optional[str] = Field(None, description="Force specific model")
    skip_cache: bool = Field(False, description="Skip cache lookup")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")


class ProcessResponse(BaseModel):
    """Response from processing."""
    blocked: bool = Field(..., description="Whether request was blocked")
    reason: Optional[str] = Field(None, description="Reason if blocked")
    cached: bool = Field(..., description="Whether response was from cache")
    response: Optional[str] = Field(None, description="Cached response if available")
    recommended_model: Optional[str] = Field(None, description="Recommended model to use")
    threat_level: str = Field(..., description="Detected threat level")
    action: str = Field(..., description="Action taken")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional details")


class RecordRequest(BaseModel):
    """Request to record a completed response."""
    text: str = Field(..., description="Original user input")
    response: str = Field(..., description="LLM response")
    model: str = Field(..., description="Model that was used")
    tokens: Dict[str, int] = Field(..., description="Token counts (input, output)")
    user_id: Optional[str] = Field(None, description="User ID for feedback")
    system_prompt: Optional[str] = Field(None, description="System prompt used")
    cache_response: bool = Field(True, description="Whether to cache this response")


class RecordResponse(BaseModel):
    """Response from recording."""
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    cached: bool


class ScanRequest(BaseModel):
    """Request to scan text for threats."""
    text: str = Field(..., min_length=1, max_length=50000, description="Text to scan")


class ScanResponse(BaseModel):
    """Response from scanning."""
    is_safe: bool
    threats: list
    risk_score: Optional[float] = None


class ConfigRequest(BaseModel):
    """Request to update platform configuration."""
    protection_level: Optional[str] = Field(None, description="relaxed, standard, strict")
    enable_injection_detection: Optional[bool] = None
    enable_anomaly_detection: Optional[bool] = None
    enable_smart_routing: Optional[bool] = None
    enable_caching: Optional[bool] = None
    rate_limit_rpm: Optional[int] = None
    rate_limit_rph: Optional[int] = None


class ProjectScanRequest(BaseModel):
    """Request to scan a project for auto-configuration."""
    project_path: str = Field(..., description="Path to the project to scan")


# =============================================================================
# Platform Instance Management
# =============================================================================

_platform_instance: Optional[InALign] = None


def get_platform_instance() -> InALign:
    """Get or create the platform instance."""
    global _platform_instance
    if _platform_instance is None:
        _platform_instance = InALign()
    return _platform_instance


def set_platform_instance(platform: InALign):
    """Set the platform instance."""
    global _platform_instance
    _platform_instance = platform


# =============================================================================
# Core Endpoints
# =============================================================================

@router.post("/process", response_model=ProcessResponse)
async def process_request(
    request: ProcessRequest,
    http_request: Request,
    platform: InALign = Depends(get_platform_instance)
):
    """
    Process a user request through all security and efficiency layers.

    This is the main endpoint - call this for every user request.

    Flow:
    1. Security check (injection detection, rate limiting, anomaly detection)
    2. Efficiency optimization (cache lookup, model routing)
    3. Return recommendation or cached response
    """
    try:
        # Get real IP if not provided
        ip_address = request.ip_address
        if not ip_address:
            ip_address = http_request.client.host if http_request.client else None

        result = platform.process(
            text=request.text,
            user_id=request.user_id,
            ip_address=ip_address,
            system_prompt=request.system_prompt,
            force_model=request.force_model,
            skip_cache=request.skip_cache,
            metadata=request.metadata,
        )

        return ProcessResponse(**result)

    except Exception as e:
        logger.error(f"Process error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/record", response_model=RecordResponse)
async def record_response(
    request: RecordRequest,
    platform: InALign = Depends(get_platform_instance)
):
    """
    Record a completed LLM response for analytics and caching.

    Call this after getting the LLM response.
    """
    try:
        result = platform.record(
            text=request.text,
            response=request.response,
            model=request.model,
            tokens=request.tokens,
            user_id=request.user_id,
            system_prompt=request.system_prompt,
            cache_response=request.cache_response,
        )

        return RecordResponse(**result)

    except Exception as e:
        logger.error(f"Record error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan", response_model=ScanResponse)
async def scan_text(
    request: ScanRequest,
    platform: InALign = Depends(get_platform_instance)
):
    """
    Scan text for threats without full processing.

    Useful for quick security checks.
    """
    try:
        result = platform.scan(request.text)

        return ScanResponse(
            is_safe=result.get("is_safe", True),
            threats=result.get("threats", []),
            risk_score=result.get("risk_score"),
        )

    except Exception as e:
        logger.error(f"Scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Statistics & Monitoring
# =============================================================================

@router.get("/stats")
async def get_stats(platform: InALign = Depends(get_platform_instance)):
    """
    Get comprehensive platform statistics.

    Returns security, efficiency, and usage metrics.
    """
    try:
        return platform.get_stats()
    except Exception as e:
        logger.error(f"Stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats/user/{user_id}")
async def get_user_stats(
    user_id: str,
    platform: InALign = Depends(get_platform_instance)
):
    """
    Get statistics for a specific user.

    Includes request history, threat score, rate limit status.
    """
    try:
        stats = platform.get_user_stats(user_id)
        if stats is None:
            raise HTTPException(status_code=404, detail="User not found")
        return stats
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Configuration
# =============================================================================

@router.post("/config")
async def update_config(
    request: ConfigRequest,
    platform: InALign = Depends(get_platform_instance)
):
    """
    Update platform configuration.

    Changes take effect immediately.
    """
    try:
        changes = {}

        if request.protection_level:
            platform.set_protection_level(request.protection_level)
            changes["protection_level"] = request.protection_level

        if request.rate_limit_rpm is not None:
            platform.shield.rate_limiter.requests_per_minute = request.rate_limit_rpm
            changes["rate_limit_rpm"] = request.rate_limit_rpm

        if request.rate_limit_rph is not None:
            platform.shield.rate_limiter.requests_per_hour = request.rate_limit_rph
            changes["rate_limit_rph"] = request.rate_limit_rph

        return {"status": "updated", "changes": changes}

    except Exception as e:
        logger.error(f"Config error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/config/scan-project")
async def scan_project(
    request: ProjectScanRequest,
    platform: InALign = Depends(get_platform_instance)
):
    """
    Scan a project and auto-configure the platform.

    Analyzes the project to detect:
    - LLM providers used
    - Frameworks
    - Security patterns
    - Optimization opportunities

    Then auto-configures protection level and routing.
    """
    try:
        result = platform.configure_from_project(request.project_path)
        return result
    except Exception as e:
        logger.error(f"Project scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# User Management
# =============================================================================

@router.post("/users/{user_id}/unban")
async def unban_user(
    user_id: str,
    platform: InALign = Depends(get_platform_instance)
):
    """
    Manually unban a user.

    Use when a user was incorrectly banned.
    """
    try:
        success = platform.unban_user(user_id)
        if success:
            return {"status": "unbanned", "user_id": user_id}
        else:
            raise HTTPException(status_code=404, detail="User not found or not banned")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unban error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/cache")
async def clear_cache(platform: InALign = Depends(get_platform_instance)):
    """
    Clear the response cache.

    Useful for development or when cached responses become stale.
    """
    try:
        platform.clear_cache()
        return {"status": "cache_cleared"}
    except Exception as e:
        logger.error(f"Clear cache error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Health Check
# =============================================================================

@router.get("/health")
async def health_check(platform: InALign = Depends(get_platform_instance)):
    """
    Health check endpoint.

    Returns platform status and version.
    """
    return {
        "status": "healthy",
        "version": platform.VERSION,
        "components": {
            "detector": platform.detector is not None,
            "shield": platform.shield is not None,
            "efficiency": platform.efficiency is not None,
        }
    }
