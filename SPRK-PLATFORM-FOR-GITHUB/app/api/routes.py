"""
API Routes for SPR{K}3 Platform
REST API endpoints for analysis and monitoring
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List
import sys
import os

# Add parent directory to path to import sprk3_engine
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

router = APIRouter()


class AnalysisRequest(BaseModel):
    """Request model for code analysis"""
    repository_url: str
    branch: Optional[str] = "main"
    scan_type: str = "full"  # "full", "security", "architecture"


class AnalysisResponse(BaseModel):
    """Response model for analysis results"""
    analysis_id: str
    status: str
    patterns_detected: int
    security_alerts: int
    survivor_patterns: int
    recommendations: List[str]


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_codebase(request: AnalysisRequest):
    """
    Analyze a codebase using SPR{K}3 engine
    
    Args:
        request: Analysis request with repository URL
        
    Returns:
        Analysis results with patterns, alerts, recommendations
    """
    # TODO: Clone repository, run analysis, return results
    # For now, return mock response
    
    return AnalysisResponse(
        analysis_id="mock-analysis-123",
        status="completed",
        patterns_detected=47,
        security_alerts=3,
        survivor_patterns=12,
        recommendations=[
            "🏗️ Found 12 survivor patterns - review before refactoring",
            "🛡️ 3 security patterns detected - review recommended"
        ]
    )


@router.get("/analysis/{analysis_id}")
async def get_analysis(analysis_id: str):
    """Get analysis results by ID"""
    # TODO: Fetch from database
    return {
        "analysis_id": analysis_id,
        "status": "completed",
        "message": "Analysis results"
    }


@router.get("/stats")
async def get_stats():
    """Get platform statistics"""
    return {
        "total_analyses": 1247,
        "patterns_detected": 58392,
        "security_alerts": 1834,
        "active_users": 156
    }


@router.post("/scan")
async def quick_scan(repo_path: str):
    """
    Quick scan of local repository
    
    Args:
        repo_path: Local path to repository
        
    Returns:
        Scan results
    """
    try:
        from sprk3_engine import SPRK3Engine
        
        engine = SPRK3Engine()
        result = engine.analyze_codebase(repo_path)
        
        return {
            "status": "success",
            "statistics": result.statistics,
            "security_alerts": len(result.security_alerts),
            "survivor_patterns": len(result.survivor_patterns),
            "recommendations": result.recommendations
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
