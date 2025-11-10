# Make tasks for MCP Scanner

.PHONY: help install py-check run harness vuln build-harness build-all clean

help:
	@echo "Targets:"
	@echo "  install        - Create venv and install Python deps"
	@echo "  py-check       - Syntax check (compileall)"
	@echo "  run ARGS=...   - Run Python CLI (main.py)"
	@echo "  harness        - Run Go testharness (OIDC+MCP mock)"
	@echo "  vuln           - Run Go vulnerable MCP server"
	@echo "  build-harness  - Build Go binaries into bin/"
	@echo "  build-all      - Build both Go binaries"
	@echo "  clean          - Remove build artifacts"

install:
	python -m venv .venv
	./.venv/Scripts/python -m pip install --upgrade pip
	if [ -f requirements.txt ]; then ./.venv/Scripts/python -m pip install -r requirements.txt; fi

py-check:
	python -m compileall .

run:
	python main.py $(ARGS)

harness:
	cd testharness && go run .

vuln:
	cd vuln-mcp && go run .

build-harness:
	mkdir -p bin
	cd testharness && go build -o ../bin/testharness .
	cd vuln-mcp && go build -o ../bin/vuln-mcp .

build-all: build-harness

clean:
	rm -rf bin dist .pytest_cache __pycache__ **/__pycache__ .venv