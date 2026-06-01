import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from app.database import engine, Base
from app.routers import auth, scan, dashboard
from app.routers import posts, admin
import app.models.post                # posts 테이블 자동 생성용
import app.models.admin              # admins 테이블 자동 생성용
import app.models.report             # reports 테이블 자동 생성용
import app.models.email_verification  # email_verifications 테이블 자동 생성용

limiter = Limiter(key_func=get_remote_address)

# 환경변수로 허용 origin 관리 (배포 시 FRONTEND_URL 설정)
_extra_origin = os.getenv("FRONTEND_URL", "")
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
if _extra_origin:
    ALLOWED_ORIGINS.append(_extra_origin)


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="Malicious Site Detector API", version="1.0.0", lifespan=lifespan)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# scan 라우터: /api/scan, /api/sites, /api/reports 경로를 직접 포함
app.include_router(scan.router, prefix="/api", tags=["scan"])
app.include_router(auth.router, prefix="/api", tags=["auth"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"])
app.include_router(posts.router, tags=["posts"])
app.include_router(admin.router, tags=["admin"])


@app.get("/")
def root():
    return {"status": "ok", "service": "Malicious Site Detector API"}
