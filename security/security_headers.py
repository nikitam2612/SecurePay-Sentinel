
from fastapi import Request


async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Avoid breaking FastAPI Swagger documentation
    if request.url.path not in ["/docs", "/redoc"]:
        response.headers["Content-Security-Policy"] = "default-src 'self'"

    return response
