import os
from collections import defaultdict, deque
from threading import Lock
from time import monotonic

from fastapi import HTTPException, UploadFile


LOCAL_ALLOWED_ORIGINS = ["http://127.0.0.1:5500", "http://localhost:5500"]
DEFAULT_ALLOWED_HOSTS = ["localhost", "127.0.0.1", "*.onrender.com"]


def get_csv_env(name: str, default: list[str]) -> list[str]:
    raw_value = (os.getenv(name) or "").strip()
    if not raw_value:
        return default

    values = [value.strip() for value in raw_value.split(",") if value.strip()]
    return values or default


def get_bool_env(name: str, default: bool) -> bool:
    raw_value = (os.getenv(name) or "").strip().lower()
    if not raw_value:
        return default
    return raw_value in {"1", "true", "yes", "on"}


def get_int_env(name: str, default: int) -> int:
    raw_value = (os.getenv(name) or "").strip()
    if not raw_value:
        return default

    try:
        return int(raw_value)
    except ValueError:
        return default


class SimpleRateLimiter:
    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: defaultdict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        now = monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            request_times = self._requests[key]

            while request_times and request_times[0] < cutoff:
                request_times.popleft()

            if len(request_times) >= self.max_requests:
                return False

            request_times.append(now)
            return True


async def read_limited_upload(file: UploadFile, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total_bytes = 0
    chunk_size = 1024 * 1024

    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break

        total_bytes += len(chunk)
        if total_bytes > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum supported upload size is {max_bytes // (1024 * 1024)} MB.",
            )

        chunks.append(chunk)

    return b"".join(chunks)
