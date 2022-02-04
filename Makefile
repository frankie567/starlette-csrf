isort-src:
	isort ./starlette_csrf ./tests

format: isort-src
	black .
	mypy starlette_csrf/

test:
	pytest --cov=starlette_csrf/ --cov-report=term-missing --cov-fail-under=100

bumpversion-major:
	bumpversion major

bumpversion-minor:
	bumpversion minor

bumpversion-patch:
	bumpversion patch
