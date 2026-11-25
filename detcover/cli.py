"""Command line: `demo` writes the fictional Fabrikam Logistics data to sample_data/ and builds the outputs; `review` runs
on your own files."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import report, simulate
from .checks import pl, review, summary
from .model import load

OUTPUTS = ("report.html", "detection-pack.md", "coverage.csv", "sources-review.csv", "rules-review.csv", "noise.csv", "findings.csv", "actions.csv")


def run(data: Path, out: Path, title: str | None = None) -> dict:
    d = load(data)
    rv = review(d)
    title = title or f"{d.settings.organisation} · Sentinel detection coverage"
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.html").write_text(report.render_html(d, rv, title), encoding="utf-8")
    (out / "detection-pack.md").write_text(report.pack_md(d, rv, title), encoding="utf-8")
    report.write_csv(out / "coverage.csv", rv.coverage, ["technique", "name", "tactic", "priority", "rules", "enabled", "working", "status", "rule_names", "why"])
    report.write_csv(out / "sources-review.csv", rv.sources, ["source", "table", "owner", "critical", "state", "last_record", "hours", "gb_day", "gb_before",
                                                              "change", "rules"])
    report.write_csv(out / "rules-review.csv", rv.rules, ["rule", "kind", "enabled", "severity", "source", "tactics", "techniques", "tables", "state",
                                                          "failures", "incidents", "true_positive", "fp_rate", "version", "latest", "findings"])
    report.write_csv(out / "noise.csv", rv.noise, ["rule", "incidents", "true_positive", "benign_positive", "false_positive", "undetermined",
                                                   "unclassified", "open", "fp_rate", "median_triage_h"])
    report.write_findings(rv, out / "findings.csv")
    report.write_actions(rv, out / "actions.csv")
    return summary(d, rv)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="detcover", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    dm = sub.add_parser("demo", help="write the fictional data to sample_data/ and build the outputs")
    dm.add_argument("--data", type=Path, default=Path("sample_data"))
    dm.add_argument("--out", type=Path, default=Path("output"))
    rv = sub.add_parser("review", help="build the outputs from your own files")
    rv.add_argument("data", type=Path, help="folder with rules.csv, priorities.csv and optionally sources.csv, tables.csv, ingestion.csv, incidents.csv and health.csv")
    rv.add_argument("--out", type=Path, default=Path("output"))
    rv.add_argument("--title", help="title of the report and the pack")
    a = p.parse_args(argv)
    try:
        if a.cmd == "demo":
            simulate.write(a.data)
            sm = run(a.data, a.out)
        else:
            sm = run(a.data, a.out, a.title)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"{sm['status']}: {sm['score']} % of priority techniques covered by a working rule ({sm['covered']} of {sm['priorities']}, high priority "
          f"{sm['high_score']} %), {sm['working']} of {sm['enabled']} enabled rules working, {pl(sm['sources_down'], 'expected source')} down, "
          f"{pl(sm['incidents'], 'incident')}, {sm['red']} red and {sm['amber']} amber findings, {pl(sm['decisions'], 'decision')}")
    print(f"outputs in {a.out}/: {', '.join(OUTPUTS)}")
    return 0
