"""
GitHub Webhook Handler
Handles events from GitHub App
"""

from fastapi import APIRouter, Request, HTTPException, Header
from typing import Optional
import hmac
import hashlib
import os
import json

router = APIRouter()


def verify_signature(payload: bytes, signature: str) -> bool:
    """Verify GitHub webhook signature"""
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "").encode()
    expected_signature = "sha256=" + hmac.new(
        secret, payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected_signature, signature)


@router.post("/github")
async def github_webhook(
    request: Request,
    x_github_event: Optional[str] = Header(None),
    x_hub_signature_256: Optional[str] = Header(None)
):
    """
    Handle GitHub webhook events
    
    Supported events:
    - push: Triggered on git push
    - pull_request: Triggered on PR events
    - installation: App installed/uninstalled
    """
    # Get raw payload
    payload = await request.body()
    
    # Verify signature (in production)
    if os.getenv("ENV") == "production":
        if not x_hub_signature_256:
            raise HTTPException(status_code=403, detail="No signature provided")
        if not verify_signature(payload, x_hub_signature_256):
            raise HTTPException(status_code=403, detail="Invalid signature")
    
    # Parse payload
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    # Handle different event types
    if x_github_event == "push":
        return await handle_push_event(data)
    elif x_github_event == "pull_request":
        return await handle_pull_request_event(data)
    elif x_github_event == "installation":
        return await handle_installation_event(data)
    else:
        return {"message": f"Event {x_github_event} received but not handled"}


async def handle_push_event(data: dict):
    """Handle push events - run SPR{K}3 analysis"""
    repository = data.get("repository", {}).get("full_name")
    pusher = data.get("pusher", {}).get("name")
    commits = len(data.get("commits", []))
    
    print(f"📊 Push event: {pusher} pushed {commits} commits to {repository}")
    
    # TODO: Trigger SPR{K}3 analysis asynchronously
    # from app.analysis.sprk3_engine import SPRK3Engine
    # engine = SPRK3Engine()
    # result = engine.analyze_codebase(...)
    
    return {
        "status": "received",
        "event": "push",
        "repository": repository,
        "commits": commits,
        "message": "Analysis queued"
    }


async def handle_pull_request_event(data: dict):
    """Handle pull request events"""
    action = data.get("action")
    pr_number = data.get("pull_request", {}).get("number")
    repository = data.get("repository", {}).get("full_name")
    
    print(f"🔀 PR event: {action} on PR #{pr_number} in {repository}")
    
    if action in ["opened", "synchronize"]:
        # TODO: Run SPR{K}3 analysis on PR changes
        # Post results as PR comment
        pass
    
    return {
        "status": "received",
        "event": "pull_request",
        "action": action,
        "pr": pr_number
    }


async def handle_installation_event(data: dict):
    """Handle app installation events"""
    action = data.get("action")
    installation_id = data.get("installation", {}).get("id")
    account = data.get("installation", {}).get("account", {}).get("login")
    
    print(f"⚙️ Installation event: {action} for {account} (ID: {installation_id})")
    
    if action == "created":
        # TODO: Store installation in database
        # Grant access to private repos
        pass
    elif action == "deleted":
        # TODO: Remove installation from database
        # Revoke access
        pass
    
    return {
        "status": "received",
        "event": "installation",
        "action": action,
        "account": account
    }
