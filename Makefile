PYTHON=python3

.PHONY: clean coverage nosetests tox sdist
.DEFAULT: nosetests

nosetests:
	$(PYTHON) -c "import nose; nose.run()" --where . wirepy

coverage:
	$(PYTHON) -c "import nose; nose.run()" --where . wirepy --with-coverage --cover-html --cover-package=wirepy --cover-branches --cover-inclusive --cover-erase

clean:
	-rm -r .tox/
	-rm -r build/
	-rm -r cover/
	-rm -r dist/
	-rm -r wirepy.egg-info/
	-rm MANIFEST
	-rm `find . -name \*.py[co]`
	-rm -r `find . -name __pycache__`
	-rm -r autom4te.cache
	-rm aclocal.m4
	-rm config.{status,log}
	-cd docs && make clean

tox:
	tox

sdist:
	$(PYTHON) setup.py sdist
