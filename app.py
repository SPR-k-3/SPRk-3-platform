from fastapi import FastAPI

app = FastAPI(
    title="SPR{K}3 Platform API",
    description="Bio-Inspired Code Intelligence",
    version="1.0.0"
)

@app.get("/")
async def root():
    return {
        "status": "operational",
        "service": "SPR{K}3 Platform",
        "products": ["SPR{K}3 Core", "Sentinel Security"]
    }

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.get("/pricing")
async def pricing():
    return {
        "core": {
            "starter": "$29/month",
            "professional": "$99/month",
            "business": "$299/month"
        },
        "sentinel": {
            "starter": "$49/month",
            "professional": "$149/month",
            "business": "$399/month"
        },
        "bundle": "$59/month (save 25%)"
    }
