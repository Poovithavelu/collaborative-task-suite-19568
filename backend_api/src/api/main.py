from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.api.auth import router as auth_router

openapi_tags = [
    {
        "name": "Authentication",
        "description": "Endpoints for user registration, login, and organization context switching.",
    }
]

app = FastAPI(
    title="CollabTask Backend API",
    description="REST API for CollabTask including authentication, org-aware context, and more.",
    version="0.1.0",
    openapi_tags=openapi_tags,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/", summary="Health Check", tags=["Authentication"])
def health_check():
    """Simple health check endpoint."""
    return {"message": "Healthy"}

# Register routers
app.include_router(auth_router)
