pyvenv=pyvenv-3.4
venv_dir=local/venv

check: venv
	$(venv_dir)/bin/pytest -vv tests

venv: $(venv_dir)/requirements-installed

$(venv_dir)/requirements-installed: setup.py
	test -d $(venv_dir) || $(pyvenv) $(venv_dir)
	$(venv_dir)/bin/pip install -U pip wheel
	$(venv_dir)/bin/pip install -e .
	$(venv_dir)/bin/pip install -r requirements-tests.txt
	touch $@

.PHONY: check venv
