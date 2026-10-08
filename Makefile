.PHONY: install test lint run demo clean
install:
	pip install -e ".[dev]"
test:
	pytest --cov=threatscribe --cov-report=term-missing
lint:
	ruff check threatscribe tests
run:
	uvicorn threatscribe.main:app --reload --port 8000
demo:
	python -m threatscribe.cli demo
clean:
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov
