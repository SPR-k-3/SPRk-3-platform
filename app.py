from fastapi import FastAPI

app = FastAPI(
    title="SPR{K}3 Platform API",
    description="4-Engine ML Security Platform with Cognitive Health Monitoring",
    version="2.0.0"
)

@app.get("/")
async def root():
    return {
        "status": "operational",
        "service": "SPR{K}3 Platform v2.0",
        "engines": 4,
        "products": ["SPR{K}3 Core", "SPR{K}3 Professional", "SPR{K}3 Enterprise"]
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "engines_active": 4}

@app.get("/pricing")
async def pricing():
    return {
        "core": {
            "price": "$99/month",
            "engines": 3,
            "features": ["250-sample detection", "Architecture analysis", "20 scans/month"],
            "brain_guard": False
        },
        "professional": {
            "price": "$399/month",
            "engines": 4,
            "features": ["All Core features", "BrainGuard Engine 4", "Cognitive health monitoring", "100 scans/month"],
            "brain_guard": True,
            "value_prop": "Prevents 17.7% performance degradation"
        },
        "enterprise": {
            "price": "$1,299/month",
            "engines": 4,
            "features": ["All Professional features", "Unlimited scans", "Priority support", "SLA"],
            "brain_guard": True
        },
        "roi": "One prevented brain rot incident = 22 months of Professional tier"
    }
