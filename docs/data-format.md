# Data format

Up to seven CSV files and a settings file in one folder. Comma or semicolon, UTF-8 or UTF-16. Column names are
forgiving: the names in brackets are also accepted. `rules.csv` and `priorities.csv` are required; without the others
the checks that need them have nothing to look at. `scripts/Export-SentinelDetectionCoverage.ps1` writes `rules.csv`,
`tables.csv`, `ingestion.csv`, `incidents.csv` and `health.csv` (read-only). `sources.csv` and `priorities.csv` are the
organisation's own lists.

## rules.csv

| Column | Meaning |
|---|---|
| Rule (DisplayName) | Rule name |
| Kind (Type) | `Scheduled`, `NRT`, `Fusion`, `MicrosoftSecurityIncidentCreation`, … |
| Enabled | `yes`/`no` or `True`/`False` |
| Severity | `High`, `Medium`, `Low`, `Informational` |
| Tactics | Separated by `;` |
| Techniques | ATT&CK technique and sub-technique IDs, separated by `;` (`T1110.003`) |
| Tables (DataTypes) | The tables the query reads, separated by `;`. The exporter finds them by matching the workspace's table names in the query, so a table built inside the query, a function or a watchlist may need adding by hand |
| Frequency (QueryFrequency) | How often it runs, as exported (`PT1H`) |
| Source | `Custom`, `Template` (or `Content hub`), `Microsoft` |
| TemplateVersion, LatestVersion | The version the rule was created from and the template's current version |
| Modified (LastModifiedUtc) | Last change |

## priorities.csv

| Column | Meaning |
|---|---|
| Technique (TechniqueId) | ATT&CK ID: `T1078`, `T1110.003` |
| Name | Technique name |
| Tactic | For the report |
| Priority | `high` or `medium`: a gap on a high one is RED |
| Why | Why it matters here (optional) |

A rule mapped to a technique covers it and its sub-techniques; a rule mapped to a sub-technique covers the parent too.
The list is the organisation's own choice from its threat model: the demo's is an example, not a recommendation.

## sources.csv

| Column | Meaning |
|---|---|
| Source | Name of the log source |
| Table | The table it lands in |
| Owner | Who fixes it |
| Critical | `yes`: silent or missing is RED and the decision is due today |
| MaxDelayHours | Hours without a record before it counts as silent (default `silent_hours`) |

## tables.csv, ingestion.csv

| File | Columns |
|---|---|
| tables.csv | Table, LastRecord (the newest TimeGenerated) |
| ingestion.csv | Date, Table, GB (one row per table and day, from the `Usage` table) |

Without `tables.csv` the last day with ingestion stands in for the last record.

## incidents.csv

| Column | Meaning |
|---|---|
| Incident (IncidentNumber) | Number |
| Title | Title |
| Rule | The analytics rule that raised it |
| Severity | `High`, `Medium`, `Low`, `Informational` |
| Status | `New`, `Active`, `Closed` |
| Classification | `TruePositive`, `BenignPositive`, `FalsePositive`, `Undetermined` or empty |
| Owner (AssignedTo) | Analyst |
| Created (CreatedTime) | When it was created |
| FirstModified (FirstModifiedTime) | The first change by an analyst: the triage time |
| Closed (ClosedTime) | When it was closed |

## health.csv

| Column | Meaning |
|---|---|
| Time (TimeGenerated) | When the rule ran |
| Rule (SentinelResourceName) | Rule name |
| Status | `Success`, `Failure`, `Partial success` |
| Reason (Description) | What went wrong |

The exporter writes every run that did not succeed plus the last run of each rule; a rule whose newest row is a failure is
failing now.

## settings.json

| Setting | Default | Meaning |
|---|---|---|
| organisation | | Name in the title |
| review | now | When the review runs |
| days | 30 | Incidents and rule health looked at |
| silent_hours | 24 | No record for this long: silent (per source in `MaxDelayHours`) |
| drop_pct | 50 | Last week's daily volume this much below the weeks before |
| unused_gb | 1.0 | A table with this many GB a day that no enabled rule reads |
| noisy_min, noisy_pct | 10, 80 | A rule with at least this many classified incidents and this share of false or benign positives |
| triage_hours | High 4, Medium 24, Low 72 | Target from creation to the first change |
| late_pct | 25 | Share over the target that is too many, even with a good median |
| open_days | 7 | A High incident open longer than this |
| unclassified_pct | 20 | Share of closed incidents with no classification |
| score_amber, score_red | 90, 75 | Coverage below these turns the result amber or red |
| previous_score | | Last review's coverage, for the trend |
| owners | | `soc`, `engineering` and `platform` |

## The checks

| Code | When | Severity |
|---|---|---|
| SOURCE-SILENT | An expected source has no record for longer than its limit | RED if critical, AMBER otherwise |
| SOURCE-MISSING | An expected source never arrived | RED if critical, AMBER otherwise |
| SOURCE-DROP | Last week's daily volume is `drop_pct` below the weeks before | AMBER |
| TABLE-NO-RULES | A table outside sources.csv with `unused_gb` a day that no enabled rule reads | AMBER |
| RULE-BLIND | Enabled rules that read a silent or missing table: only that table (cannot fire) or among others | RED; AMBER |
| RULE-FAILING | The last run failed; or runs failed in the period and the last one worked | RED; AMBER |
| RULE-DISABLED | A disabled rule mapped to a priority technique | AMBER |
| RULE-NO-MAPPING | Enabled scheduled or NRT rules with no technique | AMBER |
| RULE-OUTDATED | Rules on an older version of their template | AMBER |
| GAP-NONE | A priority technique with no enabled rule | RED if high, AMBER if medium |
| GAP-BROKEN | A priority technique whose enabled rules are all failing or blind | RED if high, AMBER if medium |
| RULE-NOISY | `noisy_min` classified incidents and `noisy_pct` false or benign | AMBER |
| TRIAGE-SLOW | High or Medium: median over the target, or more than `late_pct` over it | AMBER |
| TRIAGE-OPEN | High incidents open longer than `open_days` | RED |
| UNCLASSIFIED | Closed incidents with no classification above `unclassified_pct` | AMBER |

## The score

A rule **works** when it is enabled, its last run did not fail and every table it reads is receiving data (a drop in
volume still counts as receiving). The score is the share of priority techniques with at least one working rule; the
high-priority share is shown next to it.
