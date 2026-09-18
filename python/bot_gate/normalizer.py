"""Incoming web request normalization for bot-gate."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import parse_qs, urlparse

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
    body: Any = None
    ip: str | None = None
    url: str = "/"


@dataclass
class RequestContext:
    missing_browser_headers: list[str] = field(default_factory=list)
    suspicious_signatures: list[str] = field(default_factory=list)
    claims_browser: bool = False
    is_known_search_bot: bool = False
    rate_count: int | None = None


def normalize_request(request_input: Any) -> tuple[NormalizedRequest, RequestContext]:
    method = "GET"
    path = "/"
    query: dict[str, Any] = {}
    headers: dict[str, str] = {}
    body: Any = None
    ip: str | None = None

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

        raw_headers = request_input.get("headers", {})
        if isinstance(raw_headers, (dict, Mapping)):
            for k, v in raw_headers.items():
                headers[str(k).lower()] = str(v)

        body = request_input.get("body")
        ip = request_input.get("ip") or headers.get("x-forwarded-for", "").split(",")[0].strip() or None

    # Support for FastAPI/Starlette Request objects
    elif hasattr(request_input, "scope") and hasattr(request_input, "headers"):
        req = request_input
        method = getattr(req, "method", "GET").upper()
        path = req.url.path if hasattr(req, "url") else "/"
        if hasattr(req, "query_params"):
            query = dict(req.query_params)
        for k, v in req.headers.items():
            headers[k.lower()] = v
        if hasattr(req, "client") and req.client:
            ip = req.client.host
        ip = headers.get("x-forwarded-for", "").split(",")[0].strip() or ip

    # Support for WSGI environ
    elif isinstance(request_input, dict) and "REQUEST_METHOD" in request_input:
        env = request_input
        method = env.get("REQUEST_METHOD", "GET").upper()
        path = env.get("PATH_INFO", "/")
        qs = env.get("QUERY_STRING", "")
        if qs:
            query = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(qs).items()}
        for k, v in env.items():
            if k.startswith("HTTP_"):
                header_name = k[5:].replace("_", "-").lower()
                headers[header_name] = str(v)
        headers["content-type"] = env.get("CONTENT_TYPE", "")
        ip = env.get("REMOTE_ADDR")

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
        if "sec-ch-ua" not in headers and "firefox/" not in user_agent:
            missing_browser_headers.append("sec-ch-ua")

    suspicious_signatures: list[str] = []
    for tool in KNOWN_ATTACK_TOOLS:
        if tool in user_agent:
            suspicious_signatures.append(f"known_attack_tool:{tool}")

    norm_req = NormalizedRequest(
        method=method,
        path=path,
        query=query,
        headers=headers,
        body=body,
        ip=ip,
        url=path,
    )

    ctx = RequestContext(
        missing_browser_headers=missing_browser_headers,
        suspicious_signatures=suspicious_signatures,
        claims_browser=claims_browser,
        is_known_search_bot=is_known_search_bot,
    )

    return norm_req, ctx
