from typing import Optional, Set, cast

from itsdangerous import BadSignature
from itsdangerous.url_safe import URLSafeSerializer
from passlib.pwd import genword
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp


class CSRFMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        secret: str,
        cookie_name: str = "csrftoken",
        cookie_path: str = "/",
        cookie_domain: Optional[str] = None,
        header_name: str = "x-csrftoken",
        safe_methods: Set[str] = {"GET", "HEAD", "OPTIONS", "TRACE"},
    ) -> None:
        super().__init__(app)
        self.serializer = URLSafeSerializer(secret, "csrftoken")
        self.secret = secret
        self.cookie_name = cookie_name
        self.cookie_path = cookie_path
        self.cookie_domain = cookie_domain
        self.header_name = header_name
        self.safe_methods = safe_methods

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        csrf_cookie = request.cookies.get(self.cookie_name)

        if request.method not in self.safe_methods:
            csrf_header = request.headers.get(self.header_name)
            if (
                not csrf_cookie
                or not csrf_header
                or not self._csrf_tokens_match(csrf_cookie, csrf_header)
            ):
                return PlainTextResponse(
                    content="CSRF token verification failed", status_code=403
                )

        response = await call_next(request)

        if not csrf_cookie:
            response.set_cookie(
                self.cookie_name,
                self._generate_csrf_token(),
                path=self.cookie_path,
                domain=self.cookie_domain,
            )

        return response

    def _generate_csrf_token(self) -> str:
        return cast(str, self.serializer.dumps(genword(entropy="strong")))

    def _csrf_tokens_match(self, token1: str, token2: str) -> bool:
        try:
            decoded1: str = self.serializer.loads(token1)
            decoded2: str = self.serializer.loads(token2)
            return decoded1 == decoded2
        except BadSignature:
            return False
