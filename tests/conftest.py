import asyncio
import re
from typing import Callable

import httpx
import pytest
from asgi_lifespan import LifespanManager
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from starlette_csrf import CSRFMiddleware


@pytest.fixture(scope="session")
def event_loop():
    """Force the pytest-asyncio loop to be the main one."""
    loop = asyncio.get_event_loop()
    yield loop


@pytest.fixture(scope="session")
def all_sensitive_csrfmiddleware() -> Middleware:
    return Middleware(CSRFMiddleware, secret="SECRET")


@pytest.fixture(scope="session")
def some_sensitive_csrfmiddleware() -> Middleware:
    return Middleware(CSRFMiddleware, secret="SECRET", sensitive_cookies={"sensitive"})


@pytest.fixture(scope="session")
def some_exempt_csrfmiddleware() -> Middleware:
    return Middleware(
        CSRFMiddleware, secret="SECRET", exempt_urls=[re.compile(r"/exempt")]
    )


@pytest.fixture
def app_generator() -> Callable[[Middleware], Starlette]:
    def _app_generator(middleware: Middleware) -> Starlette:
        async def get(request: Request):
            return JSONResponse({"hello": "world"})

        async def post(request: Request):
            json = await request.json()
            return JSONResponse(json)

        app = Starlette(
            debug=True,
            routes=[
                Route("/get", get, methods=["GET"]),
                Route("/post", post, methods=["POST"]),
                Route("/exempt", post, methods=["POST"]),
            ],
            middleware=[middleware],
        )

        return app

    return _app_generator


@pytest.fixture
async def test_client_all_sensitive(app_generator, all_sensitive_csrfmiddleware):
    app = app_generator(all_sensitive_csrfmiddleware)
    async with LifespanManager(app):
        async with httpx.AsyncClient(app=app, base_url="http://app.io") as test_client:
            yield test_client


@pytest.fixture
async def test_client_some_sensitive(app_generator, some_sensitive_csrfmiddleware):
    app = app_generator(some_sensitive_csrfmiddleware)
    async with LifespanManager(app):
        async with httpx.AsyncClient(app=app, base_url="http://app.io") as test_client:
            yield test_client


@pytest.fixture
async def test_client_some_exempt(app_generator, some_exempt_csrfmiddleware):
    app = app_generator(some_exempt_csrfmiddleware)
    async with LifespanManager(app):
        async with httpx.AsyncClient(app=app, base_url="http://app.io") as test_client:
            yield test_client
