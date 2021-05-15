from typing import Dict

import httpx
import pytest
from starlette import status


@pytest.mark.asyncio
async def test_get(test_client: httpx.AsyncClient):
    response = await test_client.get("/get")

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
    test_client: httpx.AsyncClient, cookies: Dict[str, str], headers: Dict[str, str]
):
    response = await test_client.post("/post", cookies=cookies, headers=headers)

    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_valid_csrf(test_client: httpx.AsyncClient):
    response_get = await test_client.get("/get")
    csrf_cookie = response_get.cookies["csrftoken"]

    response_post = await test_client.post(
        "/post",
        headers={"x-csrftoken": csrf_cookie},
        json={"hello": "world"},
    )

    assert response_post.status_code == status.HTTP_200_OK
