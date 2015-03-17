# Makefile

results.csv: projects_to_examine.csv oss_package_analysis.py
	time python -t -3 oss_package_analysis.py -p projects_to_examine.csv

DISTRIBUTABLES = results.csv projects_to_examine.csv oss_package_analysis.py \
	oss-needing-help.docx dataflow-analysis.pptx \
	Makefile README \
	oss-results.xlsx \
	apt_cache_dumpavail.txt Black-Duck-Letter-6SJan2015.pdf

# The oss-results.xlsx file is manually created from results.csv.

# Use "make dist" to create archive of distributable information
dist: oss-metrics.tgz

oss-metrics.tgz: FORCE
	mkdir oss-metrics-latest/
	cp -p $(DISTRIBUTABLES) oss-metrics-latest/
	tar cvzf oss-metrics.tgz oss-metrics-latest/
	rm -fr oss-metrics-latest/

FORCE:
