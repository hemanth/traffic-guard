"""Incoming web request normalization for traffic-guard."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import parse_qs, urlparse

from .crypto import parse_cookies

KNOWN_GOOD_BOTS = [
    "googlebot",
    "bingbot",
    "yandexbot",
    "duckduckbot",
    "slurp",
    "baiduspider",
    "facebookexternalhit",
    "twitterbot",
    "linkedinbot",
    "embedly",
    "slackbot",
    "w3c_validator",
    "uptime",
]

KNOWN_ATTACK_TOOLS = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "acunetix",
    "dirbuster",
    "gobuster",
    "wfuzz",
    "burpcollaborator",
    "hydra",
    "havij",
]


@dataclass
class NormalizedRequest:
    method: str = "GET"
    path: str = "/"
    query: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    raw_headers: list[str] = field(default_factory=list)
    body: Any = None
    ip: str | None = None
    url: str = "/"
    cookies: dict[str, str] = field(default_factory=dict)


@dataclass
class RequestContext:
    missing_browser_headers: list[str] = field(default_factory=list)
    suspicious_signatures: list[str] = field(default_factory=list)
    claims_browser: bool = False
    is_known_search_bot: bool = False
    header_order_anomaly: bool = False
    rate_count: int | None = None
    is_honeypot: bool = False


def check_header_order_anomaly(raw_headers: list[str], user_agent: str) -> bool:
    if not raw_headers or len(raw_headers) < 3:
        return false if False else False

    order = [h.lower() for h in raw_headers]
    ua = user_agent.lower()
    claims_chromium = "chrome/" in ua or "edg/" in ua

    try:
        host_idx = order.index("host")
    except ValueError:
        host_idx = -1

    try:
        ua_idx = order.index("user-agent")
    except ValueError:
        ua_idx = -1

    try:
        sec_ch_ua_idx = order.index("sec-ch-ua")
    except ValueError:
        sec_ch_ua_idx = -1

    # Anomaly 1: User-Agent before Host
    if ua_idx != -1 and host_idx != -1 and ua_idx < host_idx:
        return True

    # Anomaly 2: Chromium client hint after accept-encoding
    if claims_chromium and sec_ch_ua_idx != -1:
        try:
            accept_enc_idx = order.index("accept-encoding")
            if sec_ch_ua_idx > accept_enc_idx + 2:
                return True
        except ValueError:
            pass

    return False


def normalize_request(request_input: Any) -> tuple[NormalizedRequest, RequestContext]:
    method = "GET"
    path = "/"
    query: dict[str, Any] = {}
    headers: dict[str, str] = {}
    raw_headers: list[str] = []
    body: Any = None
    ip: str | None = None
    cookies: dict[str, str] = {}

    if isinstance(request_input, str):
        parsed = urlparse(request_input)
        path = parsed.path or "/"
        if parsed.query:
            query = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()}
    elif isinstance(request_input, Mapping):
        method = str(request_input.get("method", "GET")).upper()
        raw_url = request_input.get("url") or request_input.get("path") or "/"
        parsed = urlparse(raw_url)
        path = parsed.path or "/"
        if parsed.query:
            query.update({k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()})

        if "query" in request_input and isinstance(request_input["query"], dict):
            query.update(request_input["query"])

        raw_headers_input = request_input.get("raw_headers")
        if isinstance(raw_headers_input, list):
            raw_headers = [str(h) for h in raw_headers_input]

        raw_headers_dict = request_input.get("headers", {})
        if isinstance(raw_headers_dict, (dict, Mapping)):
            for k, v in raw_headers_dict.items():
                headers[str(k).lower()] = str(v)
                if not raw_headers:
                    raw_headers.append(str(k))

        body = request_input.get("body")
        ip = request_input.get("ip") or headers.get("x-forwarded-for", "").split(",")[0].strip() or None
        cookies = request_input.get("cookies") or parse_cookies(headers.get("cookie", ""))

    # Support for FastAPI/Starlette Request objects
    elif hasattr(request_input, "scope") and hasattr(request_input, "headers"):
        req = request_input
        method = getattr(req, "method", "GET").upper()
        path = req.url.path if hasattr(req, "url") else "/"
        if hasattr(req, "query_params"):
            query = dict(req.query_params)
        for k, v in req.headers.items():
            headers[k.lower()] = v
            raw_headers.append(k)
        if hasattr(req, "client") and req.client:
            ip = req.client.host
        ip = headers.get("x-forwarded-for", "").split(",")[0].strip() or ip
        cookies = dict(req.cookies) if hasattr(req, "cookies") else parse_cookies(headers.get("cookie", ""))

    # Support for ASGI scope
    elif isinstance(request_input, dict) and "headers" in request_input and isinstance(request_input["headers"], list):
        scope = request_input
        method = scope.get("method", "GET").upper()
        path = scope.get("path", "/")
        for k, v in scope["headers"]:
            k_str = k.decode("latin1") if isinstance(k, bytes) else str(k)
            v_str = v.decode("latin1") if isinstance(v, bytes) else str(v)
            headers[k_str.lower()] = v_str
            raw_headers.append(k_str)
        client = scope.get("client")
        ip = client[0] if client else None
        cookies = parse_cookies(headers.get("cookie", ""))

    user_agent = headers.get("user-agent", "").lower()
    claims_browser = "mozilla/" in user_agent and any(
        b in user_agent for b in ("chrome/", "safari/", "firefox/", "edg/")
    )
    is_known_search_bot = any(bot in user_agent for bot in KNOWN_GOOD_BOTS)

    missing_browser_headers: list[str] = []
    if claims_browser and not is_known_search_bot:
        if "accept-language" not in headers:
            missing_browser_headers.append("accept-language")
        if "accept-encoding" not in headers:
            missing_browser_headers.append("accept-encoding")
        is_chromium = "chrome/" in user_agent or "edg/" in user_agent
        if is_chromium and "sec-ch-ua" not in headers:
            missing_browser_headers.append("sec-ch-ua")

    suspicious_signatures: list[str] = []
    for tool in KNOWN_ATTACK_TOOLS:
        if tool in user_agent:
            suspicious_signatures.append(f"known_attack_tool:{tool}")

    header_order_anomaly = check_header_order_anomaly(raw_headers, user_agent)

    norm_req = NormalizedRequest(
        method=method,
        path=path,
        query=query,
        headers=headers,
        raw_headers=raw_headers,
        body=body,
        ip=ip,
        url=path,
        cookies=cookies,
    )

    ctx = RequestContext(
        missing_browser_headers=missing_browser_headers,
        suspicious_signatures=suspicious_signatures,
        claims_browser=claims_browser,
        is_known_search_bot=is_known_search_bot,
        header_order_anomaly=header_order_anomaly,
    )

    return norm_req, ctx
