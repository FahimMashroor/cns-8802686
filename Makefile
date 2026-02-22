# Website Fingerprinting - Makefile
# =================================

.PHONY: help venv activate deactivate install capture extract all clean stats run

help:
	@echo "Environment:"
	@echo "  venv        - Create virtual environment and install dependencies"
	@echo "  activate    - Show activation command"
	@echo "  deactivate  - Show deactivation command"
	@echo "  install     - Install Python dependencies"
	@echo ""
	@echo "Dataset:"
	@echo "  capture     - Collect traffic from websites (sudo required)"
	@echo "  extract     - Extract features from PCAP files"
	@echo "  all         - Run full pipeline: capture + extract"
	@echo "  clean       - Remove generated CSV files"
	@echo "  stats       - Show collection statistics"
	@echo ""
	@echo "Run:"
	@echo "  run         - Open Jupyter notebook of paper reimplementation"

# Environment
venv:
	python3.12 -m venv venv

activate:
	@echo "Run: source venv/bin/activate"

deactivate:
	@echo "Run: deactivate"

install:
	pip install -r requirements.txt

# Dataset
capture:
	@if [ "$$(id -u)" -ne 0 ]; then echo "Run with: sudo make capture"; exit 1; fi
	bash bin/collect_all.sh

extract:
	python scripts/extract_features.py

all: capture extract

stats:
	@echo "Collection Statistics"
	@echo "====================="
	@for label in google youtube wikipedia reddit github stackoverflow amazon; do \
		count=$$(find data/experiment/capture_files -name "$${label}_trace*.pcap" 2>/dev/null | wc -l | tr -d ' '); \
		printf "  %-15s %3d traces\n" "$${label}:" "$${count}"; \
	done
	@total=$$(find data/experiment/capture_files -name "*.pcap" 2>/dev/null | wc -l | tr -d ' '); \
	echo ""; echo "  Total PCAP: $${total}"

# Run
run:
	jupyter notebook notebooks/reimplementation.ipynb
