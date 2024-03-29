# Makefile
#
# A normal development cycle usually involves:
#
#     make venv-create
#     . venv/bin/activate
#     make install-dev
#     # no longer needed: make install-local-deps
#     make test
#     # make changes and test them
#     make clean
#     make venv-delete
#
# This Python package has a "setup.py" script. Therefore, it can be
# normally installed by running "pip install ." which will run it.
# According to the forums, running it directly with "python setup.py
# install" can cause problems, so it is safer to run it via
# pip. Running "make install-normal" does exactly that.
#
# When working on this package, you don't want to install it
# normally. That will make a copy of the files, so any changes made to
# the sources won't be used (the unchanged copy that was installed
# will be used). Instead, install a link to this package. This can be
# done by running "make install-dev".
#
# When this package is installed (either as a copy or as a link) a
# copy of its dependent packages are also installed. But if this
# package depends on changes made to a dependency, those changes won't
# be available until they are published and then installed. Instead,
# if a local copy of the dependent package is available, links to it
# can be used (so its local changes are immediately available). Run
# "make install-local-dep" to establish those links. Note: do this
# after running "make install-dev" (otherwise copies of the
# dependencies indentified in setup.py will replace the links).

.PHONY: test

help:
	@echo "Targets:"
	@echo "  venv-create        - create virtual environment"
	@echo "  venv-delete        - delete virtual environment"
	@echo "  venv-reset         - delete and create a new dev-rsa + venv"
#	@echo "  venv-reset         - delete and create a new dev-rsa + local-deps venv"
	@echo
	@echo "  install-dev        - install as a link (in venv)"
	@echo "  install-dev-rsa    - install as a link (in venv) with RSA support"
#	@echo "  install-local-deps - install dependencies as links (in venv)"
	@echo "  install-normal     - install a copy (in current environment)"
	@echo "  install-normal-rsa - install a copy (in current environment) with RSA support"
	@echo
	@echo "  test               - run unit tests"
	@echo
	@echo "  publish            - publish to PyPi"
	@echo
	@echo "  clean              - delete all generated files (except venv)"
	@echo
	@echo 'See the comments in the "Makefile" for more information.'

#----------------------------------------------------------------

VENV=venv

venv-create:
	@if [ ! -e "${VENV}" ]; then \
	  echo "venv-create: creating ${VENV}" && \
	  python3 -m venv "${VENV}" && \
	  echo "venv-create: upgrading pip and setuptools" && \
	  . ${VENV}/bin/activate && \
	  pip install --upgrade pip && \
	  pip install --upgrade setuptools && \
	  echo "venv-create: activate by sourcing '${VENV}/bin/activate'" ; \
	else \
	  echo "venv-create: already exists: ${VENV}"; \
	fi

venv-delete:
	@rm -rf "${VENV}"

# Delete any current venv and recreate it.

venv-reset: venv-delete venv-create install-dev-rsa

# removed from above dependencies: install-local-deps

#----------------------------------------------------------------

install-dev:
	@if [ -e venv ]; then \
	  . venv/bin/activate && \
	  echo "install-dev: installing this package development" && \
          pip install --editable . ; \
	else \
	  echo "install-dev: venv does not exist"; \
	  exit 1 ; \
	fi

install-dev-rsa:
	@if [ -e venv ]; then \
	  . venv/bin/activate && \
	  echo "install-dev-rsa: installing this package development" && \
          pip install --editable '.[rsa]' ; \
	else \
	  echo "install-dev-rsa: venv does not exist"; \
	  exit 1 ; \
	fi

#install-local-deps:
#	@if [ -e venv ]; then \
#	  . venv/bin/activate && \
#	  DIR=`cd .. && pwd` && \
#	  for PKG in 'oauthlib' ; do \
#	    if [ -d "$${DIR}/$${PKG}" ]; then \
#	      PKGDIR="file://$${DIR}/$${PKG}" ; \
#	      echo "linking $${PKG} to $${PKGDIR}"; \
#	      pip install --editable "$${PKGDIR}" ; \
#	    else \
#	      echo "Error: local copy of package not found: $${PKG}" ; \
#	      exit 1 ; \
#	    fi \
#	  done \
#	else \
#	  echo "install-local-deps: venv does not exist"; \
#	  exit 1 ; \
#	fi

install-normal:
	pip install .

install-normal-rsa:
	pip install '.[rsa]'

#----------------------------------------------------------------

test:
	@python3 test/test_httpie_oauth1.py

#----------------------------------------------------------------
# Publishing to PyPi
# https://medium.com/@joel.barmettler/how-to-upload-your-python-package-to-pypi-65edc5fe9c56

publish:
	rm -f dist/*.tar.gz
	python setup.py sdist
	twine upload dist/*

#----------------------------------------------------------------

clean:
	@rm -f *~
	@rm -rf *.egg-info __pycache__ build doc dist
