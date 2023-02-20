import contextlib
import re
from typing import Dict

import httpx
import pytest
from asgi_lifespan import LifespanManager
from starlette import status
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from starlette_csrf import CSRFMiddleware


def get_app(**middleware_kwargs) -> Starlette:
    async def get(request: Request):
        return JSONResponse({"hello": "world"})

    async def post(request: Request):
        json = await request.json()
        return JSONResponse(json)

    app = Starlette(
        debug=True,
        routes=[
            Route("/get", get, methods=["GET"]),
            Route("/post1", post, methods=["POST"]),
            Route("/post2", post, methods=["POST"]),
        ],
        middleware=[Middleware(CSRFMiddleware, secret="SECRET", **middleware_kwargs)],
    )

    return app


@contextlib.asynccontextmanager
async def get_test_client(app: Starlette):
    async with LifespanManager(app):
        async with httpx.AsyncClient(app=app, base_url="http://app.io") as test_client:
            yield test_client


@pytest.mark.asyncio
async def test_get():
    async with get_test_client(get_app()) as client:
        response = await client.get("/get")

        assert response.status_code == status.HTTP_200_OK

        assert "csrftoken" in response.cookies

        set_cookie_header = response.headers["set-cookie"]
        assert "Path=/;" in set_cookie_header
        assert "HttpOnly" not in set_cookie_header
        assert "Secure" not in set_cookie_header


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cookies,headers",
    [
        ({}, {}),
        ({}, {"x-csrftoken": "aaa"}),
        ({"csrftoken": "aaa"}, {}),
        ({"csrftoken": "aaa"}, {"x-csrftoken": "aaa"}),
    ],
)
async def test_post_invalid_csrf(cookies: Dict[str, str], headers: Dict[str, str]):
    async with get_test_client(get_app()) as client:
        response = await client.post("/post1", cookies=cookies, headers=headers)

        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_valid_csrf():
    async with get_test_client(get_app()) as client:
        response_get = await client.get("/get")
        csrf_cookie = response_get.cookies["csrftoken"]

        response_post = await client.post(
            "/post1",
            headers={"x-csrftoken": csrf_cookie},
            json={"hello": "world"},
        )

        assert response_post.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_required_urls():
    async with get_test_client(get_app(required_urls=[re.compile(r"/get")])) as client:
        response_get_required = await client.get("/get")
        assert response_get_required.status_code == status.HTTP_403_FORBIDDEN

    async with get_test_client(
        get_app(required_urls=[re.compile(r"/post1")], sensitive_cookies={"sensitive"})
    ) as client:
        response_post_required = await client.post(
            "/post1",
            json={"hello": "world"},
        )
        assert response_post_required.status_code == status.HTTP_403_FORBIDDEN

        response_get = await client.get("/get")
        assert response_get.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_exempt_urls():
    async with get_test_client(get_app(exempt_urls=[re.compile(r"/post1")])) as client:
        response_post_exempt = await client.post(
            "/post1",
            cookies={"foo": "bar"},
            json={"hello": "world"},
        )
        assert response_post_exempt.status_code == status.HTTP_200_OK

        response_post_not_exempt = await client.post(
            "/post2",
            cookies={"sensitive": "bar"},
            json={"hello": "world"},
        )
        assert response_post_not_exempt.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_sensitive_cookies():
    async with get_test_client(get_app(sensitive_cookies={"sensitive"})) as client:
        response_get = await client.get("/get")
        csrf_cookie = response_get.cookies["csrftoken"]

        response_post_not_sensitive = await client.post(
            "/post1",
            cookies={"foo": "bar"},
            json={"hello": "world"},
        )
        assert response_post_not_sensitive.status_code == status.HTTP_200_OK

        response_post_sensitive_no_csrf_token = await client.post(
            "/post1",
            cookies={"sensitive": "bar"},
            json={"hello": "world"},
        )
        assert (
            response_post_sensitive_no_csrf_token.status_code
            == status.HTTP_403_FORBIDDEN
        )

        response_post_sensitive_csrf_token = await client.post(
            "/post1",
            cookies={"sensitive": "bar"},
            headers={"x-csrftoken": csrf_cookie},
            json={"hello": "world"},
        )
        assert response_post_sensitive_csrf_token.status_code == status.HTTP_200_OK
