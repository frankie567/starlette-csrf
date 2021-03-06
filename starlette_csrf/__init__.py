"""Starlette middleware implementing Double Submit Cookie technique to mitigate CSRF."""

__version__ = "1.4.4"

from starlette_csrf.middleware import CSRFMiddleware  # noqa: F401
