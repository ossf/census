# Makefile

results.csv: projects_to_examine.csv oss_package_analysis.py
	time python -t -3 oss_package_analysis.py -p projects_to_examine.csv

# "make check" runs tests using data in "test_dataset/".
# No network access is needed for the test (cached data is used)
check:
	echo "Running test.  Will produce error if results are unexpected."
	cd test_dataset ; \
	python -t -3 ../oss_package_analysis.py -p projects_to_examine.csv && \
	diff -u correct_results.csv results.csv 

# "make analyze" runs static analysis on source code
# Must have "pyflakes" installed
analyze:
	pyflakes oss_package_analysis.py

# "make pylint" runs the "pylint" static analyzer.  It's helpful,
# but version 1.1.0 (on Ubuntu 14) produces false positives
# (for example, it complains about some variables not following the constant
# naming convention.. but they aren't constants).  Some of its issues
# take longer to address, too.  So we currently have this as a *separate*
# target, and someday we'll merge this into "analyze".
pylint:
	pylint --rcfile=.pylintrc oss_package_analysis.py 

# When creating a tarball, here's what goes in it.
# The oss-results.xlsx file is manually created from results.csv.
DISTRIBUTABLES = results.csv projects_to_examine.csv oss_package_analysis.py \
	oss-needing-help.docx dataflow-analysis.pptx \
	Makefile README \
	oss-results.xlsx \
	test_dataset/ \
	apt_cache_dumpavail.txt Black-Duck-Letter-6SJan2015.pdf

# Use "make dist" to create archive of distributable information
dist: oss-metrics.tgz

oss-metrics.tgz: FORCE
	mkdir oss-metrics-latest/
	cp -pr $(DISTRIBUTABLES) oss-metrics-latest/
	tar cvzf oss-metrics.tgz oss-metrics-latest/
	rm -fr oss-metrics-latest/

# Bogus target to force execution (even on really old versions of make)
FORCE:

.PHONY: check analyze pylint dist FORCE
