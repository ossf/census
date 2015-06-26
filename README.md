# Core Infrastructure Initiative Census

Automated review of open source software projects

This project contains programs and documentation to help identify
open source software (OSS) projects that may need additional investment
to improve security.

Key files include:

* [OSS-2015-06-19.pdf](OSS-2015-06-19.pdf): Detailed documentation about this work.
* [projects_to_examine.csv](projects_to_examine.csv): CSV file listing OSS projects to be examined, as well as data that requires human input
* [oss_package_analysis.py](oss_package_analysis.py): Python program that reads projects_to_examine.csv to determine the OSS projects to examine.  It gathers data from a a variety of data sources, caching where it can. It produces results.csv.
* [results.csv](results.csv): CSV file listing OSS projects and related metrics.

The Python analysis program is released under the MIT license and requires "BeautifulSoup" to work. The program requires an [API key](https://github.com/blackducksw/ohloh_api#api-key) from Black Duck Open Hub to work.

The documentation is released under the Creative Commons CC-BY license.

Some supporting data was sourced from the Black Duck Open HUB (formerly Ohloh), a free online community resource for discovering, evaluating, tracking and comparing open source code and projects.  We thank Black Duck for the data!

# Description of this project

The Heartbleed vulnerability in OpenSSL highlighted that while some open source
software (OSS) is widely used and depended on, vulnerabilities can have
serious ramifications, and yet some projects have not received the level of
security analysis appropriate to their importance. Some OSS projects have many
participants, perform in-depth security analyses, and produce software that is
widely considered to have high quality and strong security. However, other
OSS projects have small teams that have limited time to do the tasks necessary
for strong security. The trick is to identify which critical projects
fall into the second bucket.

We have focused on automatically gathering metrics, especially those that
suggest less active projects. We also provided a human estimate of the
program's exposure to attack, and developed a scoring system to heuristically
combine these metrics. These heuristics identified especially plausible
candidates for further consideration. For our initial set of projects to
examine, we took the set of packages installed by Debian base and added a set
of packages that were identified as potentially concerning.

We invite you to contribute in the following ways:
* fork the repository and try different metrics and heuristics. Send us pull
requests for the ones that you find experimentally make the most sense.
* fork the repository and try different data sources.
* review the data in projects_to_examine.csv and send corrections and elaborations.
* suggest more projects to consider in the future.
* open an issue to mention additional relevant literature in the field.

# Background

This work was sponsored by the Linux Foundation's Core Infrastructure Initiative
