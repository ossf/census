#!/bin/bash

# Script to import the results.csv into a temporary SQLite database.
#
# usage: bash sqlite_results.sh [results.csv]
#
# This will start a SQLite shell with the data from results.csv in
# the table "results".

results_csv="$1"

if test -z "$results_csv" ; then
    results_csv=results.csv
fi

# Preserve original standard input.
exec 5<&0

# Skip the first line which contains the column names.
tail -n +2 -- "$results_csv" | sqlite3 -init /dev/fd/3 3<<EOF 4<&0 <&5
CREATE TABLE results (
    project_name,
    debian_source,
    debian_version,
    debian_desc,
    debian_home,
    CVE_since_2010 INTEGER,
    CVE_page,
    openhub_page,
    openhub_name,
    openhub_desc,
    openhub_home,
    openhub_download,
    twelve_month_contributor_count INTEGER,
    total_contributor_count INTEGER,
    total_code_lines INTEGER,
    main_language_name,
    licenses,
    fact_activity,
    fact_age,
    fact_comments,
    fact_team_size,
    package_popularity,
    implemented_in,
    role,
    direct_network_exposure,
    process_network_data,
    potential_privilege_escalation,
    risk_index INTEGER,
    risk_index_components,
    comment_on_priority
);
.mode csv
.import /dev/fd/4 results
UPDATE results SET twelve_month_contributor_count = NULL
  WHERE twelve_month_contributor_count = '';
UPDATE results SET total_contributor_count = NULL
  WHERE total_contributor_count = '';
UPDATE results SET total_code_lines = NULL
  WHERE total_code_lines = '';
EOF
