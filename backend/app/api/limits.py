import math

from fastapi import Depends, HTTPException, Request, status

from app.api.deps import CurrentUser
from app.core.config import get_settings
from app.core.rate_limit import RateLimiter

limiter = RateLimiter()

TOO_MANY_REQUESTS = "Too many requests. Try again later."


def client_ip(request: Request) -> str:
    if get_settings().trust_proxy_headers:
        last = request.headers.get("x-forwarded-for", "").split(",")[-1].strip()
        if last:
            return last
    return request.client.host if request.client else "unknown"


def _check(key: str, limit: int, window_seconds: int) -> None:
    if not get_settings().rate_limit_enabled:
        return
    retry_after = limiter.hit(key, limit, window_seconds)
    if retry_after is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=TOO_MANY_REQUESTS,
            headers={"Retry-After": str(math.ceil(retry_after))},
        )


def limit_by_ip(name: str, limit: int, window_seconds: int):
    def dependency(request: Request) -> None:
        _check(f"{name}:ip:{client_ip(request)}", limit, window_seconds)

    return dependency


def limit_by_user(name: str, limit: int, window_seconds: int):
    def dependency(user: CurrentUser) -> None:
        _check(f"{name}:user:{user.id}", limit, window_seconds)

    return dependency


register_limit = Depends(limit_by_ip("register", 5, 600))
login_limit = Depends(limit_by_ip("login", 10, 60))
import_limit = Depends(limit_by_user("import", 20, 60))
analysis_limit = Depends(limit_by_user("analysis", 10, 60))
ai_limit = Depends(limit_by_user("ai", 10, 60))