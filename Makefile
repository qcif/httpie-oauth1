# Makefile

.PHONY: test

help:
	@echo "Targets:"
	@echo "  test        - run unit tests"
	@echo "  create-venv - create virtual environment"
	@echo "  delete-venv - delete virtual environment"
	@echo "  clean       - delete all generated files (except venv)"

test:
	@python3 test/test_httpie_oauth1.py

create-venv:
	@if [ ! -e venv ]; then \
	  echo "create-venv: creating venv" && \
	  python3 -m venv venv && \
	  . venv/bin/activate && \
	  echo "create-venv: upgrading pip" && \
	  pip install --upgrade pip && \
	  echo "create-venv: installing for development" && \
          pip install --editable . && \
	  echo "create-venv: activate by sourcing 'venv/bin/activate'" ; \
	else \
	  echo "create-venv: venv already exists"; \
	fi

delete-venv:
	@rm -rf venv

clean:
	@rm -f *~
	@rm -rf *.egg-info __pycache__ build dist
