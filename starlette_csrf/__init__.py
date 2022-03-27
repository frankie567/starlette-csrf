"""Starlette middleware implementing Double Submit Cookie technique to mitigate CSRF."""

__version__ = "1.4.3"

from starlette_csrf.middleware import CSRFMiddleware  # noqa: F401
