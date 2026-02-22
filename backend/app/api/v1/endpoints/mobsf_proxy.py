from __future__ import annotations

from urllib.parse import urlencode

import httpx

from fastapi import APIRouter, Request as FastAPIRequest, Response

router = APIRouter()

MOBSF_BASE_URL = "https://mobsf.live"
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}
BLOCKED_RESPONSE_HEADERS = {
    "x-frame-options",
    "content-security-policy",
    "content-security-policy-report-only",
    "frame-options",
}


def _rewrite_html_for_proxy(html: str) -> str:
    proxy_prefix = "/api/v1/mobsf-proxy/"
    replacements = {
        'href="/': f'href="{proxy_prefix}',
        "href='/": f"href='{proxy_prefix}",
        'src="/': f'src="{proxy_prefix}',
        "src='/": f"src='{proxy_prefix}",
        'action="/': f'action="{proxy_prefix}',
        "action='/": f"action='{proxy_prefix}",
        "url(/": f"url({proxy_prefix}",
        "url('/": f"url('{proxy_prefix}",
        "url(\"/": f"url(\"{proxy_prefix}",
        "https://mobsf.live/": proxy_prefix,
        "http://mobsf.live/": proxy_prefix,
        "//mobsf.live/": proxy_prefix,
    }

    for old, new in replacements.items():
        html = html.replace(old, new)

    return html


def _rewrite_location_header(value: str) -> str:
    proxy_prefix = "/api/v1/mobsf-proxy/"
    if not value:
        return value

    if value.startswith("/"):
        return f"{proxy_prefix}{value.lstrip('/')}"

    if value.startswith("https://mobsf.live/"):
        return value.replace("https://mobsf.live/", proxy_prefix, 1)
    if value.startswith("http://mobsf.live/"):
        return value.replace("http://mobsf.live/", proxy_prefix, 1)
    if value.startswith("//mobsf.live/"):
        return value.replace("//mobsf.live/", proxy_prefix, 1)

    return value


def _rewrite_set_cookie_header(value: str) -> str:
    if not value:
        return value

    parts = [p.strip() for p in value.split(";")]
    rewritten: list[str] = []
    for part in parts:
        lower = part.lower()
        if lower.startswith("domain="):
            continue
        if lower.startswith("secure"):
            continue
        rewritten.append(part)
    return "; ".join(rewritten)


async def _proxy_request(path: str, incoming_request: FastAPIRequest) -> Response:
    clean_path = path.lstrip("/")
    target_url = f"{MOBSF_BASE_URL}/{clean_path}" if clean_path else f"{MOBSF_BASE_URL}/"
    if incoming_request.query_params:
        target_url = f"{target_url}?{urlencode(list(incoming_request.query_params.multi_items()))}"

    method = incoming_request.method.upper()
    body = await incoming_request.body()

    forward_headers: dict[str, str] = {}
    for key, value in incoming_request.headers.items():
        key_lower = key.lower()
        if key_lower in HOP_BY_HOP_HEADERS:
            continue
        if key_lower in {"host", "content-length"}:
            continue
        forward_headers[key] = value

    forward_headers["Referer"] = MOBSF_BASE_URL
    forward_headers["Origin"] = MOBSF_BASE_URL

    timeout = httpx.Timeout(connect=20.0, read=120.0, write=120.0, pool=20.0)

    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
            upstream = await client.request(
                method,
                target_url,
                headers=forward_headers,
                content=body if body else None,
            )

        content_type = upstream.headers.get("Content-Type", "application/octet-stream")
        status_code = upstream.status_code

        response_headers: dict[str, str] = {}
        for key, value in upstream.headers.items():
            key_lower = key.lower()
            if key_lower in HOP_BY_HOP_HEADERS or key_lower in BLOCKED_RESPONSE_HEADERS:
                continue
            if key_lower == "content-length":
                continue
            if key_lower == "location":
                response_headers[key] = _rewrite_location_header(value)
                continue
            if key_lower == "set-cookie":
                response_headers[key] = _rewrite_set_cookie_header(value)
                continue
            response_headers[key] = value

        if "text/html" in content_type.lower():
            decoded = upstream.text
            decoded = _rewrite_html_for_proxy(decoded)
            return Response(
                content=decoded,
                status_code=status_code,
                media_type="text/html",
                headers=response_headers,
            )

        return Response(
            content=upstream.content,
            status_code=status_code,
            media_type=content_type.split(";")[0],
            headers=response_headers,
        )

    except httpx.RequestError as exc:
        return Response(
            content=f"MobSF proxy connection failed: {exc}".encode("utf-8"),
            status_code=502,
            media_type="text/plain",
        )
    except Exception as exc:
        return Response(
            content=f"MobSF proxy error: {exc}".encode("utf-8"),
            status_code=500,
            media_type="text/plain",
        )


@router.get("", include_in_schema=False)
@router.get("/", include_in_schema=False)
async def proxy_root(request: FastAPIRequest) -> Response:
    return await _proxy_request("", request)


@router.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    include_in_schema=False,
)
async def proxy_path(path: str, request: FastAPIRequest) -> Response:
    return await _proxy_request(path, request)
