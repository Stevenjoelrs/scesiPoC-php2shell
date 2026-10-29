SHELL := /bin/sh
.DEFAULT_GOAL := help

COMPOSE_FILE ?= docker/compose.yml
COMPOSE := docker compose --env-file .env -f $(COMPOSE_FILE)

# Load ports/images from .env when present; fall back to the examples.
-include .env
VULN_PORT ?= 8088
PATCHED_PORT ?= 8089

# Clearly synthetic: never the real THM flag.
SYNTHETIC_FLAG ?= FLAG{php2shell_lab_synthetic_flag_redacted}

URL ?= http://127.0.0.1:$(VULN_PORT)/index.php
CMD ?= id>/out/p1

.PHONY: help env runtime compose-check lab-up lab-up-patched lab-down lab-ps lab-logs \
        lab-smoke lab-reset doctor smoke leak exploit detect matrix check test clean

help: ## Show this help
	@echo "php2shell lab -- make targets"
	@echo ""
	@echo "  make env              copy .env.example to .env (idempotent)"
	@echo "  make runtime          create runtime dirs + synthetic /f flag"
	@echo "  make compose-check    validate docker/compose.yml"
	@echo "  make lab-up           start the vulnerable target on 127.0.0.1:$(VULN_PORT)"
	@echo "  make lab-up-patched   start vuln + patched control"
	@echo "  make lab-down         stop and remove containers"
	@echo "  make lab-ps           show container status"
	@echo "  make lab-logs         follow target logs"
	@echo "  make lab-smoke        GET / and print the response"
	@echo "  make lab-reset        clear proof output from runtime/out"
	@echo "  make doctor           check Python, Docker, containers and config"
	@echo "  make smoke            GET $(URL)"
	@echo "  make leak             run the heap/libphp leak stages"
	@echo "  make exploit          full chain (CMD='cat /f>/out/p1' for the flag)"
	@echo "  make detect           passive PHP fingerprint + optional probe"
	@echo "  make matrix           vulnerable vs patched control"
	@echo "  make check            byte-compile + unit tests"
	@echo "  make test             unit tests only"
	@echo "  make clean            remove __pycache__ and build artefacts"

env:
	@test -f .env || cp .env.example .env

runtime:
	@mkdir -p runtime/out runtime/patched/out
	@test -f runtime/f || printf '%s\n' "$(SYNTHETIC_FLAG)" > runtime/f
	@chmod 0644 runtime/f
	@# Docker Desktop's VirtioFS ignores chown from inside the container, so
	@# the www-data worker can only write /out if the host dir is world-writable.
	@chmod 0777 runtime/out runtime/patched/out

compose-check: env runtime
	@$(COMPOSE) config >/dev/null && echo "compose.yml: OK"

lab-up: env runtime compose-check
	@$(COMPOSE) up -d vuln
	@echo "vuln: http://127.0.0.1:$(VULN_PORT)/"

lab-up-patched: env runtime compose-check
	@$(COMPOSE) --profile patched up -d vuln patched
	@echo "vuln:    http://127.0.0.1:$(VULN_PORT)/"
	@echo "patched: http://127.0.0.1:$(PATCHED_PORT)/"

lab-down: env
	@$(COMPOSE) --profile patched down --remove-orphans

lab-ps: env
	@$(COMPOSE) --profile patched ps

lab-logs: env
	@$(COMPOSE) logs -f --tail=100 vuln

lab-smoke:
	@curl -fsS "$(URL)"

lab-reset:
	@rm -rf runtime/out/* runtime/patched/out/*
	@mkdir -p runtime/out runtime/patched/out
	@chmod 0777 runtime/out runtime/patched/out
	@echo "runtime output cleared"

doctor: env runtime
	@python3 -m poc doctor

smoke: env runtime
	@python3 -m poc smoke -u "$(URL)"

leak: env runtime
	@python3 -m poc leak -u "$(URL)"

exploit: env runtime
	@python3 -m poc exploit -u "$(URL)" -c '$(CMD)'

detect: env runtime
	@python3 -m poc detect -u "$(URL)"

matrix: env runtime
	@python3 -m poc matrix

check:
	@python3 -m compileall -q poc tests scripts
	@python3 -m unittest discover -s tests -v

test:
	@python3 -m unittest discover -s tests -v

clean:
	@find . -type d -name __pycache__ -prune -exec rm -rf {} +
	@rm -rf build dist *.egg-info .pytest_cache .ruff_cache
	@echo "clean"
