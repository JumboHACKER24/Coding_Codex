venv:
	python3 -m venv .venv

install: venv
	. .venv/bin/activate && python -m pip install --upgrade pip setuptools wheel && pip install -r requirements.txt

test: install
	. .venv/bin/activate && PYTHONPATH=. pytest -q

clean:
	rm -rf .venv __pycache__
