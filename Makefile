.PHONY: install dev test lint format clean docker docker-run help run setup

# ── Configuration ─────────────────────────────────────────────────────
PYTHON     ?= python3
VENV_DIR   := .venv
VENV_PY    := $(VENV_DIR)/bin/python
VENV_PIP   := $(VENV_DIR)/bin/pip
VENV_ACT   := source $(VENV_DIR)/bin/activate
SHELL       = /bin/bash

# Colors
GREEN  := \033[0;32m
YELLOW := \033[0;33m
RED    := \033[0;31m
CYAN   := \033[0;36m
NC     := \033[0m

# ── Help ──────────────────────────────────────────────────────────────
help: ## Show this help
	@echo ""
	@echo "$(CYAN)  Wafford — WiFi Auditing Framework$(NC)"
	@echo "$(CYAN)  ────────────────────────────────────$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""

# ── Create virtual environment if missing ─────────────────────────────
$(VENV_DIR)/bin/activate:
	@echo "$(YELLOW)► Creating Python virtual environment...$(NC)"
	@$(PYTHON) -m venv $(VENV_DIR)
	@echo "$(YELLOW)► Upgrading pip + setuptools + wheel...$(NC)"
	@$(VENV_PY) -m pip install --upgrade pip setuptools wheel --quiet
	@echo "$(GREEN)✓ Virtual environment ready at $(VENV_DIR)/$(NC)"

# ── Main install ──────────────────────────────────────────────────────
setup: $(VENV_DIR)/bin/activate ## One-click setup: venv + Python deps + system deps
	@echo ""
	@echo "$(CYAN)═══════════════════════════════════════════$(NC)"
	@echo "$(CYAN)  WAFFORD INSTALLER$(NC)"
	@echo "$(CYAN)═══════════════════════════════════════════$(NC)"
	@echo ""
	@echo "$(GREEN)✓ Step 1/4 — Virtual environment$(NC)"
	@echo "  $(VENV_DIR)/ ready"
	@echo ""
	@echo "$(GREEN)✓ Step 2/4 — Python dependencies$(NC)"
	@$(VENV_PIP) install -e "." --quiet 2>&1 || $(VENV_PIP) install -e "."
	@echo "  wafford + all Python packages installed"
	@echo ""
	@echo "$(GREEN)✓ Step 3/4 — System dependencies$(NC)"
	@echo "  Checking/installing WiFi tools..."
	@command -v aircrack-ng  >/dev/null 2>&1 || (echo "  → Installing aircrack-ng..."  && sudo apt-get install -y aircrack-ng  >/dev/null 2>&1) || true
	@command -v airmon-ng    >/dev/null 2>&1 || (echo "  → Installing airmon-ng..."    && sudo apt-get install -y aircrack-ng  >/dev/null 2>&1) || true
	@command -v aireplay-ng  >/dev/null 2>&1 || (echo "  → Installing aireplay-ng..."  && sudo apt-get install -y aircrack-ng  >/dev/null 2>&1) || true
	@command -v airodump-ng  >/dev/null 2>&1 || (echo "  → Installing airodump-ng..."  && sudo apt-get install -y aircrack-ng  >/dev/null 2>&1) || true
	@command -v hashcat      >/dev/null 2>&1 || (echo "  → Installing hashcat..."      && sudo apt-get install -y hashcat      >/dev/null 2>&1) || true
	@command -v hostapd      >/dev/null 2>&1 || (echo "  → Installing hostapd..."      && sudo apt-get install -y hostapd      >/dev/null 2>&1) || true
	@command -v dnsmasq      >/dev/null 2>&1 || (echo "  → Installing dnsmasq..."      && sudo apt-get install -y dnsmasq      >/dev/null 2>&1) || true
	@command -v mdk4         >/dev/null 2>&1 || (echo "  → Installing mdk4..."         && sudo apt-get install -y mdk4         >/dev/null 2>&1) || true
	@command -v macchanger   >/dev/null 2>&1 || (echo "  → Installing macchanger..."   && sudo apt-get install -y macchanger   >/dev/null 2>&1) || true
	@command -v reaver       >/dev/null 2>&1 || (echo "  → Installing reaver..."       && sudo apt-get install -y reaver       >/dev/null 2>&1) || true
	@command -v hcxdumptool  >/dev/null 2>&1 || (echo "  → Installing hcxdumptool..."  && sudo apt-get install -y hcxdumptool  >/dev/null 2>&1) || true
	@command -v hcxpcapngtool >/dev/null 2>&1 || (echo "  → Installing hcxtools..."    && sudo apt-get install -y hcxtools     >/dev/null 2>&1) || true
	@command -v iw           >/dev/null 2>&1 || (echo "  → Installing iw..."           && sudo apt-get install -y iw           >/dev/null 2>&1) || true
	@command -v rfkill       >/dev/null 2>&1 || (echo "  → Installing rfkill..."       && sudo apt-get install -y rfkill       >/dev/null 2>&1) || true
	@command -v nmap         >/dev/null 2>&1 || (echo "  → Installing nmap..."         && sudo apt-get install -y nmap         >/dev/null 2>&1) || true
	@command -v iwlist       >/dev/null 2>&1 || (echo "  → Installing wireless-tools..." && sudo apt-get install -y wireless-tools >/dev/null 2>&1) || true
	@echo "  System tools ready"
	@echo ""
	@echo "$(GREEN)✓ Step 4/4 — Setup complete$(NC)"
	@mkdir -p ~/.wafford/{logs,plugins,wordlists,captures,reports}
	@echo "  Config directory: ~/.wafford/"
	@echo ""
	@echo "$(CYAN)═══════════════════════════════════════════$(NC)"
	@echo "$(GREEN)  ✓ WAFFORD INSTALLED SUCCESSFULLY$(NC)"
	@echo ""
	@echo "  Run with:  $(CYAN)make run$(NC)"
	@echo "  Or:        $(CYAN)source .venv/bin/activate && sudo wafford$(NC)"
	@echo "$(CYAN)═══════════════════════════════════════════$(NC)"
	@echo ""

install: setup ## Alias for setup — one-click install

# ── Run wafford ───────────────────────────────────────────────────────
run: $(VENV_DIR)/bin/activate ## Launch wafford (auto-creates venv if needed)
	@echo "$(CYAN)Launching Wafford...$(NC)"
	@$(VENV_DIR)/bin/python -m wafford

# ── Dev mode ──────────────────────────────────────────────────────────
dev: $(VENV_DIR)/bin/activate ## Install in dev mode with test/lint deps
	@$(VENV_PIP) install -e ".[dev]" --quiet
	@mkdir -p ~/.wafford/{logs,plugins,wordlists,captures,reports}
	@echo "$(GREEN)✓ Dev mode installed$(NC)"

# ── Test / Lint / Format ─────────────────────────────────────────────
test: $(VENV_DIR)/bin/activate ## Run test suite
	@$(VENV_DIR)/bin/python -m pytest tests/ -v --cov=wafford --cov-report=term-missing

lint: $(VENV_DIR)/bin/activate ## Run linters (ruff + mypy)
	@$(VENV_DIR)/bin/python -m ruff check src/ tests/
	@$(VENV_DIR)/bin/python -m mypy src/wafford/

format: $(VENV_DIR)/bin/activate ## Auto-format code
	@$(VENV_DIR)/bin/python -m ruff format src/ tests/
	@$(VENV_DIR)/bin/python -m ruff check --fix src/ tests/

# ── Clean ─────────────────────────────────────────────────────────────
clean: ## Remove build artifacts + venv
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

clean-all: clean ## Remove everything including venv
	rm -rf $(VENV_DIR)
	@echo "$(GREEN)✓ Venv removed$(NC)"

# ── Docker ────────────────────────────────────────────────────────────
docker: ## Build Docker image
	docker build -t wafford:latest .

docker-run: ## Run in Docker (requires root)
	docker compose up -d

docker-stop: ## Stop Docker containers
	docker compose down

# ── Logs / Utils ──────────────────────────────────────────────────────
logs: ## Tail wafford logs
	@mkdir -p ~/.wafford/logs
	tail -f ~/.wafford/logs/wafford.log

uninstall: ## Uninstall wafford (keeps config)
	-@$(VENV_PIP) uninstall -y wafford 2>/dev/null || true
	@echo "$(GREEN)✓ Wafford uninstalled (config kept at ~/.wafford/)$(NC)"

deps: $(VENV_DIR)/bin/activate ## Check which system tools are installed
	@echo ""
	@echo "$(CYAN)  Dependency Status$(NC)"
	@echo "  ─────────────────"
	@for tool in aircrack-ng airmon-ng aireplay-ng airodump-ng hashcat hostapd dnsmasq mdk4 macchanger reaver hcxdumptool iw rfkill nmap; do \
		if command -v $$tool >/dev/null 2>&1; then \
			echo "  $(GREEN)✓$(NC) $$tool"; \
		else \
			echo "  $(RED)✗$(NC) $$tool  $(YELLOW)(missing)$(NC)"; \
		fi; \
	done
	@echo ""

info: ## Show environment info
	@echo ""
	@echo "$(CYAN)  Environment Info$(NC)"
	@echo "  ────────────────"
	@echo "  Python:   $$($(PYTHON) --version 2>&1)"
	@echo "  Venv:     $$(test -d $(VENV_DIR) && echo 'exists' || echo 'not created')"
	@echo "  Platform: $$(uname -s) $$(uname -m)"
	@echo "  Kernel:   $$(uname -r)"
	@echo "  Root:     $$(id -u 2>/dev/null && echo 'yes' || echo 'no')"
	@echo ""
