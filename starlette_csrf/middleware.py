import functools
import http.cookies
import secrets
from re import Pattern
from typing import Dict, List, Optional, Set, cast

from itsdangerous import BadSignature
from itsdangerous.url_safe import URLSafeSerializer
from starlette.datastructures import URL, MutableHeaders
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class CSRFMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        secret: str,
        sensitive_cookies: Optional[Set[str]] = None,
        cookie_name: str = "csrftoken",
        cookie_path: str = "/",
        cookie_domain: Optional[str] = None,
        cookie_secure: bool = False,
        cookie_httponly: bool = False,
        cookie_samesite: str = "lax",
        header_name: str = "x-csrftoken",
        safe_methods: Set[str] = {"GET", "HEAD", "OPTIONS", "TRACE"},
        exempt_urls: Optional[List[Pattern]] = None,
    ) -> None:
        self.app = app
        self.serializer = URLSafeSerializer(secret, "csrftoken")
        self.secret = secret
        self.sensitive_cookies = sensitive_cookies
        self.cookie_name = cookie_name
        self.cookie_path = cookie_path
        self.cookie_domain = cookie_domain
        self.cookie_secure = cookie_secure
        self.cookie_httponly = cookie_httponly
        self.cookie_samesite = cookie_samesite
        self.header_name = header_name
        self.safe_methods = safe_methods
        self.exempt_urls = exempt_urls

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):  # pragma: no cover
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        csrf_cookie = request.cookies.get(self.cookie_name)

        if (
            request.method not in self.safe_methods
            and self._has_sensitive_cookies(request.cookies)
            and not self._url_is_exempt(request.url)
        ):
            submitted_csrf_token = await self._get_submitted_csrf_token(request)
            if (
                not csrf_cookie
                or not submitted_csrf_token
                or not self._csrf_tokens_match(csrf_cookie, submitted_csrf_token)
            ):
                response = self._get_error_response(request)
                await response(scope, receive, send)
                return

        send = functools.partial(self.send, send=send, scope=scope)
        await self.app(scope, receive, send)

    async def send(self, message: Message, send: Send, scope: Scope) -> None:
        request = Request(scope)
        csrf_cookie = request.cookies.get(self.cookie_name)

        if csrf_cookie is None:
            message.setdefault("headers", [])
            headers = MutableHeaders(scope=message)

            cookie: http.cookies.BaseCookie = http.cookies.SimpleCookie()
            cookie_name = self.cookie_name
            cookie[cookie_name] = self._generate_csrf_token()
            cookie[cookie_name]["path"] = self.cookie_path
            cookie[cookie_name]["secure"] = self.cookie_secure
            cookie[cookie_name]["httponly"] = self.cookie_httponly
            cookie[cookie_name]["samesite"] = self.cookie_samesite
            if self.cookie_domain is not None:
                cookie[cookie_name]["domain"] = self.cookie_domain  # pragma: no cover
            headers.append("set-cookie", cookie.output(header="").strip())

        await send(message)

    def _has_sensitive_cookies(self, cookies: Dict[str, str]) -> bool:
        if not self.sensitive_cookies:
            return True
        for sensitive_cookie in self.sensitive_cookies:
            if sensitive_cookie in cookies:
                return True
        return False

    def _url_is_exempt(self, url: URL) -> bool:
        if not self.exempt_urls:
            return False
        for exempt_url in self.exempt_urls:
            if exempt_url.match(url.path):
                return True
        return False

    async def _get_submitted_csrf_token(self, request: Request) -> Optional[str]:
        return request.headers.get(self.header_name)

    def _generate_csrf_token(self) -> str:
        return cast(str, self.serializer.dumps(secrets.token_urlsafe(128)))

    def _csrf_tokens_match(self, token1: str, token2: str) -> bool:
        try:
            decoded1: str = self.serializer.loads(token1)
            decoded2: str = self.serializer.loads(token2)
            return secrets.compare_digest(decoded1, decoded2)
        except BadSignature:
            return False

    def _get_error_response(self, request: Request) -> Response:
        return PlainTextResponse(
            content="CSRF token verification failed", status_code=403
        )
