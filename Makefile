# Update Gaps, a Cockpit add-on: where a server misses updates
# SPDX-License-Identifier: Apache-2.0

.PHONY: all check lint

all:
	@echo "Nothing to build. Try: make check, make lint"

# Every offline test.
check:
	sh tools/check-design-files.sh

# As in CI (the tools: pip install -r test/requirements.txt).
lint:
	shellcheck --severity=warning tools/*.sh
	ruff check .
