.PHONY: install dev test lint selftest docker docker-run clean

install:
	pip install .

dev:
	pip install -e ".[dev]"

test:
	pytest -q

lint:
	ruff check src

selftest:
	yubel selftest -o yubel-selftest

docker:
	docker build -t yubel:local .

docker-run:
	docker run --rm -v "$(PWD)/out:/out" yubel:local selftest -o /out

clean:
	rm -rf build dist *.egg-info yubel-report yubel-selftest out .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
