"""
SPR{K}3 GitHub App Backend
==========================

FastAPI backend for GitHub integration and billing
"""

from fastapi import FastAPI, HTTPException, Header, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import hashlib
import hmac
import json
import os
import stripe
import httpx
from datetime import datetime
from typing import Optional, Dict, Any
import asyncio
from pathlib import Path

# Initialize FastAPI
app = FastAPI(
    title="SPR{K}3 Platform API",
    description="Bio-Inspired Code Intelligence for Pattern Detection and ML Security",
    version="1.0.0"
)

# Configuration (use environment variables in production)
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "your-webhook-secret")
GITHUB_APP_ID = os.getenv("GITHUB_APP_ID", "your-app-id")
GITHUB_PRIVATE_KEY = os.getenv("GITHUB_PRIVATE_KEY", "")
STRIPE_API_KEY = os.getenv("STRIPE_API_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

# Initialize Stripe
if STRIPE_API_KEY:
    stripe.api_key = STRIPE_API_KEY

# Import our detector
import sys
sys.path.append(str(Path(__file__).parent))
from sprk3_complete import StructuralPoisoningDetector

# Models
class ScanRequest(BaseModel):
    repository_url: str
    branch: str = "main"
    scan_type: str = "full"  # full, quick, security
    user_id: Optional[str] = None

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    repository: str
    results: Optional[Dict[str, Any]] = None
    billing: Optional[Dict[str, Any]] = None

class WebhookPayload(BaseModel):
    action: str
    repository: Dict[str, Any]
    sender: Dict[str, Any]
    installation: Optional[Dict[str, Any]] = None

# In-memory storage (use Redis/PostgreSQL in production)
scans_db = {}
billing_db = {}

# Helper Functions
def verify_github_signature(payload_body: bytes, signature: str) -> bool:
    """Verify GitHub webhook signature"""
    expected_signature = "sha256=" + hmac.new(
        GITHUB_WEBHOOK_SECRET.encode(),
        payload_body,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected_signature, signature)

def calculate_scan_price(lines_of_code: int) -> float:
    """Calculate price based on codebase size"""
    if lines_of_code <= 10000:
        return 0.05  # Small codebase
    elif lines_of_code <= 100000:
        return 0.20  # Medium codebase
    elif lines_of_code <= 1000000:
        return 0.50  # Large codebase
    else:
        return 1.00  # Enterprise codebase

async def clone_repository(repo_url: str, branch: str) -> str:
    """Clone repository for scanning"""
    import tempfile
    import subprocess
    
    temp_dir = tempfile.mkdtemp()
    try:
        # Clone the repository
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", branch, repo_url, temp_dir],
            check=True,
            capture_output=True
        )
        return temp_dir
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to clone repository: {str(e)}")

async def count_lines_of_code(directory: str) -> int:
    """Count lines of code in directory"""
    total_lines = 0
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.py', '.js', '.java', '.cpp', '.c', '.go', '.rs')):
                try:
                    with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                        total_lines += sum(1 for _ in f)
                except:
                    pass
    return total_lines

# API Endpoints
@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "operational",
        "service": "SPR{K}3 Platform API",
        "version": "1.0.0",
        "features": {
            "pattern_detection": True,
            "ml_security": True,
            "architectural_intelligence": True
        }
    }

@app.post("/scan", response_model=ScanResponse)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Create a new repository scan"""
    scan_id = hashlib.md5(f"{request.repository_url}{datetime.now()}".encode()).hexdigest()
    
    # Store scan request
    scans_db[scan_id] = {
        "id": scan_id,
        "status": "pending",
        "repository": request.repository_url,
        "branch": request.branch,
        "scan_type": request.scan_type,
        "created_at": datetime.now().isoformat(),
        "user_id": request.user_id
    }
    
    # Start scan in background
    background_tasks.add_task(perform_scan, scan_id, request)
    
    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        repository=request.repository_url
    )

async def perform_scan(scan_id: str, request: ScanRequest):
    """Perform the actual scan"""
    try:
        # Update status
        scans_db[scan_id]["status"] = "scanning"
        
        # Clone repository
        repo_path = await clone_repository(request.repository_url, request.branch)
        
        # Count lines of code for billing
        loc = await count_lines_of_code(repo_path)
        
        # Run SPR{K}3 analysis
        detector = StructuralPoisoningDetector(verbose=False)
        results = detector.analyze(repo_path)
        
        # Calculate pricing
        scan_price = calculate_scan_price(loc)
        
        # Update scan record
        scans_db[scan_id].update({
            "status": "completed",
            "results": results,
            "lines_of_code": loc,
            "price": scan_price,
            "completed_at": datetime.now().isoformat()
        })
        
        # Process billing if user_id provided
        if request.user_id:
            await process_billing(request.user_id, scan_id, scan_price)
            
        # Clean up
        import shutil
        shutil.rmtree(repo_path)
        
    except Exception as e:
        scans_db[scan_id].update({
            "status": "failed",
            "error": str(e),
            "completed_at": datetime.now().isoformat()
        })

async def process_billing(user_id: str, scan_id: str, amount: float):
    """Process billing for scan"""
    try:
        if STRIPE_API_KEY:
            # Create Stripe charge
            charge = stripe.Charge.create(
                amount=int(amount * 100),  # Convert to cents
                currency="usd",
                description=f"SPR{{K}}3 Scan - {scan_id}",
                metadata={"user_id": user_id, "scan_id": scan_id}
            )
            
            billing_db[scan_id] = {
                "charge_id": charge.id,
                "amount": amount,
                "status": "paid",
                "timestamp": datetime.now().isoformat()
            }
    except Exception as e:
        print(f"Billing error: {e}")

@app.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str):
    """Get scan status and results"""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = scans_db[scan_id]
    return ScanResponse(
        scan_id=scan_id,
        status=scan["status"],
        repository=scan["repository"],
        results=scan.get("results"),
        billing=billing_db.get(scan_id)
    )

@app.post("/webhook/github")
async def github_webhook(request: Request, x_hub_signature_256: str = Header(None)):
    """Handle GitHub webhooks"""
    body = await request.body()
    
    # Verify signature
    if x_hub_signature_256:
        if not verify_github_signature(body, x_hub_signature_256):
            raise HTTPException(status_code=401, detail="Invalid signature")
    
    payload = await request.json()
    event_type = request.headers.get("X-GitHub-Event", "unknown")
    
    # Handle different event types
    if event_type == "push":
        # Trigger scan on push
        repo_url = payload["repository"]["clone_url"]
        branch = payload["ref"].split("/")[-1]
        
        scan_request = ScanRequest(
            repository_url=repo_url,
            branch=branch,
            scan_type="quick"
        )
        
        background_tasks = BackgroundTasks()
        return await create_scan(scan_request, background_tasks)
        
    elif event_type == "pull_request":
        # Scan pull request
        if payload["action"] in ["opened", "synchronize"]:
            repo_url = payload["repository"]["clone_url"]
            branch = payload["pull_request"]["head"]["ref"]
            
            scan_request = ScanRequest(
                repository_url=repo_url,
                branch=branch,
                scan_type="security"
            )
            
            background_tasks = BackgroundTasks()
            return await create_scan(scan_request, background_tasks)
    
    return {"status": "ok"}

@app.post("/webhook/stripe")
async def stripe_webhook(request: Request, stripe_signature: str = Header(None)):
    """Handle Stripe webhooks"""
    body = await request.body()
    
    try:
        event = stripe.Webhook.construct_event(
            body, stripe_signature, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    # Handle different event types
    if event.type == "payment_intent.succeeded":
        payment_intent = event.data.object
        # Update billing records
        print(f"Payment successful: {payment_intent.id}")
        
    elif event.type == "customer.subscription.created":
        subscription = event.data.object
        # Handle new Sentinel subscription
        print(f"New subscription: {subscription.id}")
    
    return {"status": "ok"}

@app.get("/pricing")
async def get_pricing():
    """Get current pricing tiers"""
    return {
        "products": {
            "sprk3_core": {
                "name": "SPR{K}3 Core",
                "description": "Pay-per-scan architectural analysis",
                "pricing": [
                    {"tier": "small", "lines": "< 10K", "price": 0.05},
                    {"tier": "medium", "lines": "10K-100K", "price": 0.20},
                    {"tier": "large", "lines": "100K-1M", "price": 0.50},
                    {"tier": "enterprise", "lines": "> 1M", "price": 1.00}
                ]
            },
            "sentinel": {
                "name": "Sentinel Security Suite",
                "description": "Continuous ML security monitoring",
                "pricing": [
                    {"tier": "starter", "price": 49, "period": "month"},
                    {"tier": "professional", "price": 149, "period": "month"},
                    {"tier": "business", "price": 399, "period": "month"},
                    {"tier": "enterprise", "price": "custom", "period": "month"}
                ]
            }
        },
        "bundle_discount": 0.20
    }

@app.get("/stats")
async def get_stats():
    """Get platform statistics"""
    total_scans = len(scans_db)
    completed_scans = sum(1 for s in scans_db.values() if s["status"] == "completed")
    threats_detected = sum(
        len(s.get("results", {}).get("threats", []))
        for s in scans_db.values()
        if s.get("results")
    )
    
    return {
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "threats_detected": threats_detected,
        "active_subscriptions": len(billing_db),
        "platform_status": "operational"
    }

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
