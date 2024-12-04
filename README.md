[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/428/badge)](https://bestpractices.coreinfrastructure.org/projects/428)

# Core Infrastructure Initiative Census (aka Census I)

This project contains programs and documentation to help identify
open source software (OSS) projects that may need additional investment
to improve security, by combining a variety of quantitative metrics
to estimate risk.

You can see the final report derived from this work,
"Open Source Software Needing Security Investments"
by David A. Wheeler and Samir Khakimov (June 2015), via
<a href="https://openssf.org/resources/census-i-whitepaper-open-source-software-needing-security-investments/">OpenSSF
(the successor to the Core Infrastructure Initiative (CII))</a><a
href="https://openssf.org/programs/census-program-i/">*</a> or via
<a href="https://www.ida.org/research-and-publications/publications/all/o/op/open-source-software-projects-needing-security-investments">IDA</a>.
There has been follow-on work, so this final 2015 report is often
retroactively referred to as "Census I".

For a more recent related report, see the <a href="https://www.linuxfoundation.org/research/census-iii">Census III of Free and Open Software</a>
report by Frank Nagle, Kate Powell, Richie Zitomer, and David A. Wheeler (December 2024).

Key files include in this project are:

* [OSS-2015-06-19.pdf](OSS-2015-06-19.pdf): Detailed documentation about this work.
* [projects_to_examine.csv](projects_to_examine.csv): CSV file listing OSS projects to be examined, as well as data that requires human input
* [oss_package_analysis.py](oss_package_analysis.py): Python program that reads projects_to_examine.csv to determine the OSS projects to examine.  It gathers data from a variety of data sources, caching where it can. It produces [results.csv](results.csv).
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

This is not currently an active project. We provide this repository
so others can examine exactly what was done, and possibly use this
as a starting point for further analysis.

When it was active, we invited contributors to contribute via:

* [pull request](https://github.com/linuxfoundation/cii-census/pulls) -
  if you have a specific change to propose in the documentation, code, or data.
  We prefer these, since these are easy to merge and show
  exactly what the proposer has in mind.
* [issue](https://github.com/linuxfoundation/cii-census/issues) -
  if you have an idea or bug report (but no specific change to pull).
* [mailing list](https://lists.coreinfrastructure.org/mailman/listinfo/cii-census) - for general discussion of this project.

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
Changes must pass "make analyze" (which runs the static analysis tool pyflakes)
and "make test" (which runs the automated test suite).
Changes that add major new functionality *must* extend the automated test
suite as necessary to cover it.
We use the "-t" and "-3" warning flags ("-3" detects some Python 2/3 problems).

In the future we hoped to add using an additional static analysis tool,
pylint.  So changes shouldn't add new pylint reports,
and fixing pylint reports is welcome
(you can see them by running "make pylint").
It's written in Python2, but the goal is to avoid any construct that
2to3 can't automatically fix.

# Background

This work was sponsored by the Linux Foundation's [Core Infrastructure Initiative](https://www.coreinfrastructure.org/)
