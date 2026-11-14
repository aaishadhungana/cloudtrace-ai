import logging
import re
import time
import uuid

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from app.core.config import get_settings
from app.core.logging import request_id_var

logger = logging.getLogger("app.access")

REQUEST_ID_PATTERN = re.compile(r"[A-Za-z0-9-]{8,64}")
BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
HSTS_VALUE = "max-age=63072000; includeSubDomains"


def _reject_body(request: Request) -> JSONResponse | None:
    if request.method not in BODY_METHODS:
        return None
    length = request.headers.get("content-length")
    if length is None:
        if request.headers.get("transfer-encoding", "").lower() == "chunked":
            return JSONResponse({"detail": "Content-Length is required"}, status_code=411)
        return None
    if not length.isdigit():
        return JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)
    if int(length) > get_settings().max_request_bytes:
        return JSONResponse({"detail": "Request body is too large"}, status_code=413)
    return None


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming = request.headers.get("x-request-id", "")
        request_id = incoming if REQUEST_ID_PATTERN.fullmatch(incoming) else uuid.uuid4().hex
        token = request_id_var.set(request_id)
        started = time.perf_counter()
        try:
            response = await self._handle(request, call_next)
            elapsed = round((time.perf_counter() - started) * 1000)
            logger.info(
                "%s %s -> %s (%d ms)",
                request.method,
                request.url.path,
                response.status_code,
                elapsed,
            )
        finally:
            request_id_var.reset(token)
        response.headers["X-Request-ID"] = request_id
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if get_settings().is_production:
            response.headers.setdefault("Strict-Transport-Security", HSTS_VALUE)
        return response

    async def _handle(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        rejection = _reject_body(request)
        if rejection is not None:
            return rejection
        try:
            return await call_next(request)
        except Exception:
            logger.exception("Unhandled error on %s %s", request.method, request.url.path)
            return JSONResponse({"detail": "Internal server error"}, status_code=500)