# Core Infrastructure Initiative Census

Automated quantitative review of open source software projects.

This project contains programs and documentation to help identify
open source software (OSS) projects that may need additional investment
to improve security, by combining a variety of metrics.

Key files include:

* [OSS-2015-06-19.pdf](OSS-2015-06-19.pdf): Detailed documentation about this work.
* [projects_to_examine.csv](projects_to_examine.csv): CSV file listing OSS projects to be examined, as well as data that requires human input
* [oss_package_analysis.py](oss_package_analysis.py): Python program that reads projects_to_examine.csv to determine the OSS projects to examine.  It gathers data from a a variety of data sources, caching where it can. It produces [results.csv](results.csv).
* [results.csv](results.csv): CSV file listing OSS projects and related metrics.
* [by_inst](by_inst): Debian popularity statistics from http://popcon.debian.org/by_inst (you can get this from http://popcon.debian.org/ by selecting "Statistics for the whole archive sorted by fields").

The Python analysis program is released under the MIT license and requires [BeautifulSoup](http://www.crummy.com/software/BeautifulSoup/) to work. The program requires an [API key](https://github.com/blackducksw/ohloh_api#api-key) from Black Duck Open Hub to work.

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

# Collaboration

We invite you to contribute via:

* [pull request](https://github.com/linuxfoundation/cii-census/pulls) -
  if you have a specific change to propose in the documentation, code, or data.
  We prefer these, since these are easy to merge and show
  exactly what the proposer has in mind.
* [issue](https://github.com/linuxfoundation/cii-census/issues) -
  if you have an idea or bug report (but no specific change to pull).
* [mailing list](https://lists.coreinfrastructure.org/mailman/listinfo/cii-census) - for general discussion of this project.

If you have a *vulnerability* report, please privately send an email to
Marcus Streets mstreets&#64;linuxfoundation.org and
David A. Wheeler dwheeler&#64;ida.org.
Please try to use TLS encryption when you send the email
(many providers, like Gmail, will try to do this automatically).

Here are some examples of things you could do:

* try different metrics and heuristics. Send us pull
  requests for the ones that you find experimentally make the most sense.
* try different data sources.
* review the data in projects_to_examine.csv and send corrections and elaborations.
* suggest more projects to consider in the future.
* mention additional relevant literature in the field.

Changes to the Python code should generally comply with
[Python PEP 8](https://www.python.org/dev/peps/pep-0008/)
but use 2 spaces per indentation level.
It's written in Python2, but the goal is to avoid any construct that
2to3 can't automatically fix (we use the "-3" option to detect such problems).

# Background

This work was sponsored by the Linux Foundation's [Core Infrastructure Initiative](http://www.linuxfoundation.org/programs/core-infrastructure-initiative)
