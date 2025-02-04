.PHONY: help install install_to_pkg build_pkg upload_pkg run_tests_srv tests

install_to_pkg:
	pip install build
	pip install twine

build_pkg:
	python3 -m build

upload_pkg:
	python3 -m twine upload --skip-existing dist/*

run_tests_srv:
	flask --app tests/api_test.py run

tests:
	pytest tests/api_test.py
