# Starlette CSRF Middleware

Starlette middleware implementing Double Submit Cookie technique to mitigate CSRF.

[![build](https://github.com/frankie567/starlette-csrf/workflows/Build/badge.svg)](https://github.com/frankie567/starlette-csrf/actions)
[![codecov](https://codecov.io/gh/frankie567/starlette-csrf/branch/main/graph/badge.svg?token=fL49kIvrj6)](https://codecov.io/gh/frankie567/starlette-csrf)
[![PyPI version](https://badge.fury.io/py/starlette-csrf.svg)](https://badge.fury.io/py/starlette-csrf)
[![Downloads](https://pepy.tech/badge/starlette-csrf)](https://pepy.tech/project/starlette-csrf)

<p align="center">
    <a href="https://www.buymeacoffee.com/frankie567"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=frankie567&button_colour=FF5F5F&font_colour=ffffff&font_family=Lato&outline_colour=000000&coffee_colour=FFDD00"></a>
</p>

## How it works?

1. The user makes a first request with a method considered safe (by default `GET`, `HEAD`, `OPTIONS`, `TRACE`).
2. It receives in response a cookie (named by default `csrftoken`) which contains a secret value.
3. When the user wants to make an unsafe request, the server expects them to send the same secret value in a header (named by default `x-csrftoken`).
4. The middleware will then compare the secret value provided in the cookie and the header.
   * If they match, the request is processed.
   * Otherwise, a `403 Forbidden` error response is given.

This mechanism is necessary if you rely on cookie authentication in a browser. You can have more information about CSRF and Double Submit Cookie in the [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

## Installation

```bash
pip install starlette-csrf
```

## Usage with Starlette

```py
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette_csrf import CSRFMiddleware

routes = ...

middleware = [
    Middleware(CSRFMiddleware, secret="__CHANGE_ME__")
]

app = Starlette(routes=routes, middleware=middleware)
```

## Usage with FastAPI

```py
from fastapi import FastAPI
from starlette_csrf import CSRFMiddleware

app = FastAPI()

app.add_middleware(CSRFMiddleware, secret="__CHANGE_ME__")
```

## Arguments

* `secret` (`str`): Secret to sign the CSRF token value. **Be sure to choose a strong passphrase and keep it SECRET**.
* `sensitive_cookies` (`Set[str]` - `None`): Set of cookie names that should trigger the CSRF check if they are present in the request. Useful if you have other authentication methods that don't rely on cookies and don't need CSRF enforcement. If this parameter is `None`, the default, CSRF is **always** enforced.
* `cookie_name` (`str` - `csrftoken`): Name of the cookie.
* `cookie_path` `str` - `/`): Cookie path.
* `cookie_domain` (`Optional[str]` - `None`): Cookie domain. If your frontend and API lives in different sub-domains, be sure to set this argument with your root domain to allow your frontend sub-domain to read the cookie on the JavaScript side.
* `cookie_secure` (`bool` - `False`): Whether to only send the cookie to the server via SSL request.
* `cookie_samesite` (`str` - `lax`): Samesite strategy of the cookie.
* `header_name` (`str` - `x-csrftoken`): Name of the header where you should set the CSRF token.
* `safe_methods` (`Set[str]` - `{"GET", "HEAD", "OPTIONS", "TRACE"}`): HTTP methods considered safe which don't need CSRF protection.
* `exempt_urls` (`Optional[List[re.Pattern]]` - `None`): List of URL regexes that the CSRF check should be skipped on. Useful if you have any APIs that you know do not need CSRF protection.

## Customize error response

By default, a plain text response with the status code 403 is returned when the CSRF verification is failing. You can customize it by overloading the middleware class and implementing the `_get_error_response` method. It accepts in argument the original `Request` object and expects a `Response`. For example:

```py
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette_csrf import CSRFMiddleware

class CustomResponseCSRFMiddleware(CSRFMiddleware):
    def _get_error_response(self, request: Request) -> Response:
        return JSONResponse(
            content={"code": "CSRF_ERROR"}, status_code=403
        )
```

## Development

### Setup environment

You should create a virtual environment and activate it:

```bash
python -m venv venv/
```

```bash
source venv/bin/activate
```

And then install the development dependencies:

```bash
pip install -r requirements.dev.txt
```

### Run unit tests

You can run all the tests with:

```bash
make test
```

### Format the code

Execute the following command to apply `isort` and `black` formatting:

```bash
make format
```

## License

This project is licensed under the terms of the MIT license.
