# Reconta — developer & install convenience targets.
# Run `make help` for the list.

SHELL       := /bin/bash
PREFIX      ?= /usr/local
BINDIR      := $(PREFIX)/bin
INSTALL_DIR ?= /opt/reconta
SCRIPTS     := reconta.sh install.sh lib/*.sh modules/*.sh

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: lint
lint: ## Run ShellCheck on all scripts
	@command -v shellcheck >/dev/null || { echo "install shellcheck first"; exit 1; }
	shellcheck -x -S warning $(SCRIPTS)

.PHONY: syntax
syntax: ## bash -n every script
	@for f in $(SCRIPTS); do bash -n "$$f" && echo "ok $$f"; done

.PHONY: check-signatures
check-signatures: ## Validate config/signatures.txt format
	@awk '/^[[:space:]]*#/||/^[[:space:]]*$$/{next} \
	      NF!=3{print "bad line "NR": "$$0; bad=1; next} \
	      $$1!~/^[0-9]+$$/{print "non-numeric weight "NR; bad=1} \
	      END{if(bad)exit 1; print "signatures.txt OK"}' config/signatures.txt

.PHONY: smoke
smoke: ## Quick end-to-end run against example.com
	./reconta.sh example.com -p quick
	@test -f output/example.com/report.md && echo "smoke ok"

.PHONY: test
test: syntax check-signatures ## Run all offline checks

.PHONY: tools
tools: ## Install the recon toolchain (calls install.sh)
	./install.sh

.PHONY: install
install: ## Symlink `reconta` into $(BINDIR) (may need sudo)
	install -d "$(INSTALL_DIR)"
	cp -r . "$(INSTALL_DIR)/"
	chmod +x "$(INSTALL_DIR)/reconta.sh"
	ln -sf "$(INSTALL_DIR)/reconta.sh" "$(BINDIR)/reconta"
	@echo "installed → run 'reconta <target>' from anywhere"

.PHONY: uninstall
uninstall: ## Remove the symlink and installed copy
	rm -f "$(BINDIR)/reconta"
	rm -rf "$(INSTALL_DIR)"
	@echo "uninstalled (per-target snapshots in ~/.config/reconta remain)"

.PHONY: docker-build
docker-build: ## Build the Docker image
	docker build -t reconta .

.PHONY: docker-run
docker-run: ## Run in Docker: make docker-run TARGET=example.com
	docker run --rm -v "$(PWD)/loot:/opt/reconta/output" reconta $(TARGET) -p normal

.PHONY: clean
clean: ## Remove local scan output
	rm -rf output loot
