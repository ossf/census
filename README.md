# cii-analysis
Automated review of open source software projects

This work contains programs and documentation to help identify
open source software (OSS) projects that may need investment for security.
These go by various names, e.g., "high value targets".

Key files include:

*   projects_to_examine.csv : CSV file listing OSS projects to be examined, as well as data that requires human input
*   oss_package_analysis.py : Python program that reads projects_to_examine.csv to determine the OSS projects to examine.  It gathers data from a a variety of data sources, caching where it can. It produces results.csv.
*   results.csv: CSV file listing OSS projects and related metrics.
*   oss-needing-help.docx : Documentation about this work.

The Python analysis program is released under the MIT license.
The Python program requires "BeautifulSoup" to work.

The documentation is released under the Creative Commons CC-BY license.

Some supporting data was sourced from the Black Duck Open HUB (formerly Ohloh), a free online community resource for discovering, evaluating, tracking and comparing open source code and projects.  We thank Black Duck for the data!

