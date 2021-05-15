import asyncio

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
def test_app() -> Starlette:
    async def get(request: Request):
        return JSONResponse({"hello": "world"})

    async def post(request: Request):
        json = await request.json()
        return JSONResponse(json)

    middleware = [Middleware(CSRFMiddleware, secret="SECRET")]

    app = Starlette(
        debug=True,
        routes=[
            Route("/get", get, methods=["GET"]),
            Route("/post", post, methods=["POST"]),
        ],
        middleware=middleware,
    )

    return app


@pytest.fixture
async def test_client(test_app: Starlette):
    async with LifespanManager(test_app):
        async with httpx.AsyncClient(
            app=test_app, base_url="http://app.io"
        ) as test_client:
            yield test_client
