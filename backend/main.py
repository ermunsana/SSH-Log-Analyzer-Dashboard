from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from parser import InvalidLogFormatError, analyze_auth_log
from schemas import AnalyzeResponse
from security import (
    DEFAULT_ALLOWED_HOSTS,
    LOCAL_ALLOWED_ORIGINS,
    SimpleRateLimiter,
    get_bool_env,
    get_csv_env,
    get_int_env,
    read_limited_upload,
)


ENABLE_API_DOCS = get_bool_env("ENABLE_API_DOCS", True)
MAX_UPLOAD_BYTES = get_int_env("MAX_UPLOAD_BYTES", 5 * 1024 * 1024)
RATE_LIMIT_MAX_REQUESTS = get_int_env("RATE_LIMIT_MAX_REQUESTS", 10)
RATE_LIMIT_WINDOW_SECONDS = get_int_env("RATE_LIMIT_WINDOW_SECONDS", 60)


app = FastAPI(
    title="SSH Log Analyzer API",
    description="Analyze Linux auth.log files for failed SSH login attempts.",
    version="1.0.0",
    docs_url="/docs" if ENABLE_API_DOCS else None,
    redoc_url="/redoc" if ENABLE_API_DOCS else None,
    openapi_url="/openapi.json" if ENABLE_API_DOCS else None,
)

allowed_origins = get_csv_env("ALLOWED_ORIGINS", LOCAL_ALLOWED_ORIGINS)
allowed_hosts = get_csv_env("ALLOWED_HOSTS", DEFAULT_ALLOWED_HOSTS)
rate_limiter = SimpleRateLimiter(
    max_requests=RATE_LIMIT_MAX_REQUESTS,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS,
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: Request, file: UploadFile = File(...)) -> AnalyzeResponse:
    client_ip = request.client.host if request.client else "unknown"
    if not rate_limiter.allow(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many analysis requests from this IP. Please wait a minute and try again.",
        )

    if not file.filename:
        raise HTTPException(status_code=400, detail="Please upload a log file.")

    safe_filename = Path(file.filename).name
    file_content = await read_limited_upload(file, MAX_UPLOAD_BYTES)
    if not file_content.strip():
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")

    try:
        decoded_content = file_content.decode("utf-8")
    except UnicodeDecodeError:
        decoded_content = file_content.decode("utf-8", errors="ignore")

    try:
        return analyze_auth_log(decoded_content, source_name=safe_filename)
    except InvalidLogFormatError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
