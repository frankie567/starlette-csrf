from typing import Dict

import httpx
import pytest
from starlette import status


@pytest.mark.asyncio
async def test_get(test_client_all_sensitive: httpx.AsyncClient):
    response = await test_client_all_sensitive.get("/get")

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
async def test_post_invalid_csrf(
    test_client_all_sensitive: httpx.AsyncClient,
    cookies: Dict[str, str],
    headers: Dict[str, str],
):
    response = await test_client_all_sensitive.post(
        "/post", cookies=cookies, headers=headers
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_valid_csrf(test_client_all_sensitive: httpx.AsyncClient):
    response_get = await test_client_all_sensitive.get("/get")
    csrf_cookie = response_get.cookies["csrftoken"]

    response_post = await test_client_all_sensitive.post(
        "/post",
        headers={"x-csrftoken": csrf_cookie},
        json={"hello": "world"},
    )

    assert response_post.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_some_sensitive_csrf(test_client_some_sensitive: httpx.AsyncClient):
    response_get = await test_client_some_sensitive.get("/get")
    csrf_cookie = response_get.cookies["csrftoken"]

    response_post_not_sensitive = await test_client_some_sensitive.post(
        "/post",
        cookies={"foo": "bar"},
        json={"hello": "world"},
    )

    assert response_post_not_sensitive.status_code == status.HTTP_200_OK

    response_post_sensitive_no_csrf_token = await test_client_some_sensitive.post(
        "/post",
        cookies={"sensitive": "bar"},
        json={"hello": "world"},
    )

    assert (
        response_post_sensitive_no_csrf_token.status_code == status.HTTP_403_FORBIDDEN
    )

    response_post_sensitive_csrf_token = await test_client_some_sensitive.post(
        "/post",
        cookies={"sensitive": "bar"},
        headers={"x-csrftoken": csrf_cookie},
        json={"hello": "world"},
    )

    assert response_post_sensitive_csrf_token.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_some_exempt_csrf(test_client_some_exempt: httpx.AsyncClient):
    response_post_exempt = await test_client_some_exempt.post(
        "/exempt",
        cookies={"foo": "bar"},
        json={"hello": "world"},
    )

    assert response_post_exempt.status_code == status.HTTP_200_OK

    response_post_not_exempt = await test_client_some_exempt.post(
        "/post",
        cookies={"sensitive": "bar"},
        json={"hello": "world"},
    )

    assert response_post_not_exempt.status_code == status.HTTP_403_FORBIDDEN
