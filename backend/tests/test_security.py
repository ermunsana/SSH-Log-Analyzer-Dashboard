import asyncio
from io import BytesIO

from fastapi import HTTPException, UploadFile

from security import SimpleRateLimiter, read_limited_upload


def test_rate_limiter_blocks_after_limit():
    limiter = SimpleRateLimiter(max_requests=2, window_seconds=60)

    assert limiter.allow("203.0.113.10") is True
    assert limiter.allow("203.0.113.10") is True
    assert limiter.allow("203.0.113.10") is False


def test_read_limited_upload_rejects_large_files():
    file = UploadFile(filename="auth.log", file=BytesIO(b"a" * 6))

    try:
        asyncio.run(read_limited_upload(file, max_bytes=5))
    except HTTPException as exc:
        assert exc.status_code == 413
    else:
        raise AssertionError("Expected a 413 upload size error")
