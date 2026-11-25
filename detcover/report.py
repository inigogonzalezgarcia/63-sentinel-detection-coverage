"""Outputs: report.html (score and tiles, decisions, every finding by area, the priority techniques, log sources, rules,
noise per rule and triage), detection-pack.md (one page for the security operations review) and the CSVs: coverage,
sources-review, rules-review, noise, findings and actions."""
from __future__ import annotations

import csv
import html
from pathlib import Path

from .checks import AREAS, Review, pl, summary
from .model import FILES, Data

e = html.escape


def write_csv(path: Path, rows: list[dict], header: list[str]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=header, lineterminator="\n", extrasaction="ignore")
        w.writeheader()
        w.writerows([{k: ("" if r.get(k) is None else r.get(k)) for k in header} for r in rows])


def _when(x) -> str:
    return "" if not x else f"{x:%a %d %b %Y}"


def write_findings(rv: Review, path: Path) -> None:
    write_csv(path, [{"severity": f.severity, "area": AREAS[f.area], "code": f.code, "subject": f.subject, "finding": f.text, "owner": f.owner,
                      "due": f.due.strftime("%Y-%m-%d") if f.due else "", "action": f.action} for f in rv.findings],
              ["severity", "area", "code", "subject", "finding", "owner", "due", "action"])


def write_actions(rv: Review, path: Path) -> None:
    write_csv(path, [{"ref": f"A{n:03d}", "severity": f.severity, "action": f.action, "subject": f.subject, "owner": f.owner,
                      "due": f.due.strftime("%Y-%m-%d") if f.due else "", "done": ""} for n, f in enumerate(rv.findings, 1)],
              ["ref", "severity", "action", "subject", "owner", "due", "done"])


def _trend(d: Data, rv: Review) -> str:
    p = d.settings.previous_score
    if p is None:
        return ""
    diff = round(rv.score - p, 1)
    return f"{'+' if diff >= 0 else ''}{diff} points on the last review ({p} %)"


def _period(d: Data, rv: Review) -> str:
    return f"{rv.start:%d %b} to {d.settings.review:%d %b %Y}"


def pack_md(d: Data, rv: Review, title: str) -> str:
    sm = summary(d, rv)
    out = [f"# {title}", "", f"Review of {d.settings.review:%a %d %b %Y} · incidents and rule health {_period(d, rv)} · {sm['rules']} rules "
           f"({sm['enabled']} enabled) · {sm['sources']} expected sources · {sm['incidents']} incidents", "",
           f"**Result: {rv.status}** · priority techniques covered by a working rule **{rv.score} %** ({sm['covered']} of {sm['priorities']}) · "
           f"high priority **{rv.high_score} %**" + (f" · {_trend(d, rv)}" if _trend(d, rv) else ""), "", "## Decisions", ""]
    out += [f"{n}. **{x['decision']}** — {x['detail']} · {x['owner']} · by {_when(x['due'])}" for n, x in enumerate(rv.decisions, 1)] or ["None this time."]
    out += ["", "## Red findings", ""]
    out += [f"- **{f.code}** · {f.subject}: {f.text} → {f.action} · {f.owner}" for f in rv.findings if f.severity == "RED"] or ["None."]
    out += ["", "## Headlines", "",
            f"- {pl(sm['working'], 'rule')} of {sm['enabled']} enabled work today; {sm['broken']} are failing or blind.",
            f"- {pl(sm['sources_down'], 'expected source')} silent or missing.",
            f"- {sm['red']} red and {sm['amber']} amber findings, {pl(sm['decisions'], 'decision')}.",
            "", "## Priority techniques", "", "| Technique | Priority | Rules | Enabled | Working | Status |", "|---|---|---:|---:|---:|---|"]
    out += [f"| {c['technique']} {c['name']} | {c['priority']} | {c['rules']} | {c['enabled']} | {c['working']} | {c['status']} |" for c in rv.coverage]
    out += ["", "## Log sources", "", "| Source | Table | State | Last record | GB a day | Change | Rules |", "|---|---|---|---|---:|---:|---:|"]
    out += [f"| {x['source']} | {x['table']} | {x['state']} | {x['last_record'] or '—'} | {x['gb_day']} | {'' if x['change'] is None else str(x['change']) + ' %'} | {x['rules']} |"
            for x in rv.sources]
    out += ["", "## Sources", ""] + [f"- {FILES[k]} ({k}): {v} rows" for k, v in d.sources.items()]
    out += ["", "## Notes", "", "- The priority techniques, the limits and the targets are this organisation's own choice (priorities.csv and settings.json).",
            "- A rule works when it is enabled, its last run did not fail and every table it reads is receiving data.",
            "- Every finding and action: findings.csv and actions.csv; every rule: rules-review.csv.", ""]
    return "\n".join(out)


CSS = """
:root{--bg:#f2eee6;--card:#fbf8f3;--ink:#0e1a24;--muted:#5d6670;--line:#e2dccf;--ok:#1e7a4c;--warn:#a46200;--bad:#b42318;--track:#e8e2d6}
@media (prefers-color-scheme:dark){:root{--bg:#0e1a24;--card:#142331;--ink:#f2eee6;--muted:#a9b3bb;--line:#24364a;--ok:#4cc38a;
--warn:#f0a83a;--bad:#f2685c;--track:#2b333b}}
*{box-sizing:border-box}body{border-top:4px solid #c4672b}h1{font-weight:800;letter-spacing:-.025em;text-transform:uppercase;line-height:1.05}h1::before{content:"IGG · IT Ops toolkit";display:block;font:600 11px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.14em;text-transform:uppercase;color:#c4672b;margin-bottom:10px}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 18px 60px}h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:34px 0 12px}
.muted{color:var(--muted)}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-top:20px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.tile b{display:block;font-size:24px;white-space:nowrap}
.overall{display:inline-block;margin-top:14px;padding:6px 14px;border-radius:99px;font-weight:700;border:2px solid currentColor}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}tr:last-child td{border-bottom:0}.wrap{overflow-x:auto}
.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.pill{display:inline-block;white-space:nowrap;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.red{color:var(--bad)}.amber{color:var(--warn)}.green{color:var(--ok)}.grey{color:var(--muted)}td.fix{font-size:13px;color:var(--muted);min-width:200px;max-width:340px}
.bar{display:inline-block;width:90px;height:8px;border-radius:4px;background:var(--track);vertical-align:middle;margin-right:8px;overflow:hidden}
.code{white-space:nowrap;font-size:13px}.bar i{display:block;height:100%}.brk{overflow-wrap:anywhere;word-break:break-word}footer{margin-top:40px;font-size:13px}
"""
COLOUR = {"RED": "red", "AMBER": "amber", "covered": "green", "working": "green", "live": "green", "broken": "red", "none": "red", "failing": "red",
          "blind": "red", "missing": "red", "silent": "red", "partly blind": "amber", "disabled only": "amber", "drop": "amber", "disabled": "grey"}


def _pill(x: str) -> str:
    return f"<span class='pill {COLOUR.get(x, 'grey')}'>{e(x if x in ('RED', 'AMBER') else x)}</span>"


def _table(head: list[str], rows: list[str], empty: str = "Nothing to show.") -> str:
    if not rows:
        rows = [f"<tr><td colspan='{len(head)}'>{e(empty)}</td></tr>"]
    return "<div class='wrap'><table><tr>" + "".join(f"<th>{e(h)}</th>" for h in head) + "</tr>" + "".join(rows) + "</table></div>"


def _bar(score, good: float = 50, bad: float = 80, enough: bool = True) -> str:
    """Share of false and benign positives: green below `good`, red from `bad`, grey when too few incidents were classified."""
    if score is None:
        return "—"
    cls = "muted" if not enough else "ok" if score < good else "warn" if score < bad else "bad"
    return f"<span class='bar'><i style='width:{max(0, min(100, score)):.0f}%;background:var(--{cls})'></i></span>{score} %"


def _n(x) -> str:
    return "—" if x is None else e(str(x))


def render_html(d: Data, rv: Review, title: str) -> str:
    s, sm = d.settings, summary(d, rv)
    h = ["<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>",
         f"<title>{e(title)}</title><style>{CSS}</style></head><body><main>",
         f"<h1>{e(title)}</h1><p class='muted'>Review of {s.review:%a %d %b %Y %H:%M} · incidents and rule health {e(_period(d, rv))} · "
         + ", ".join(f"{FILES[k]} ({v})" for k, v in d.sources.items()) + "</p>",
         f"<span class='overall {rv.status.lower()}'>{rv.status} · {rv.score} % of priority techniques covered by a working rule</span>"
         + (f" <span class='muted'>{e(_trend(d, rv))}</span>" if _trend(d, rv) else ""), "<div class='tiles'>"]
    tiles = [("Techniques covered", f"{sm['covered']} of {sm['priorities']}"), ("High priority", f"{rv.high_score} %"),
             ("Rules working", f"{sm['working']} of {sm['enabled']}"), ("Sources down", f"{sm['sources_down']} of {sm['sources']}"),
             ("Incidents", sm["incidents"]), ("Red findings", sm["red"]), ("Amber findings", sm["amber"]), ("Decisions", sm["decisions"])]
    h += [f"<div class='tile'><span class='muted'>{e(k)}</span><b>{e(str(v))}</b></div>" for k, v in tiles] + ["</div>"]
    h.append("<h2>Decisions</h2>")
    h.append(_table(["Decision", "Detail", "Owner", "Due"], [f"<tr><td><b>{e(x['decision'])}</b></td><td class='brk'>{e(x['detail'])}</td>"
                    f"<td>{e(x['owner'])}</td><td class='num'>{e(_when(x['due']))}</td></tr>" for x in rv.decisions], "No decisions this time."))
    for area, label in AREAS.items():
        fs = [f for f in rv.findings if f.area == area]
        h.append(f"<h2>{e(label)} <span class='muted'>({len(fs)})</span></h2>")
        h.append(_table(["", "Code", "Subject", "Finding", "Action", "Owner", "Due"], [f"<tr><td>{_pill(f.severity)}</td><td class='code'>{e(f.code)}</td>"
                        f"<td class='brk'><b>{e(f.subject)}</b></td><td class='brk'>{e(f.text)}</td><td class='fix'>{e(f.action)}</td><td>{e(f.owner)}</td>"
                        f"<td class='num'>{e(_when(f.due))}</td></tr>" for f in fs], "Nothing to report."))
    h.append("<h2>Priority techniques</h2>")
    h.append(_table(["Technique", "Tactic", "Priority", "Rules", "Working", "Status", "Rules that detect it"],
                    [f"<tr><td><b>{e(c['technique'])}</b> {e(c['name'])}</td><td>{e(c['tactic'])}</td><td>{e(c['priority'])}</td>"
                     f"<td class='num'>{c['enabled']} of {c['rules']}</td><td class='num'>{c['working']}</td><td>{_pill(c['status'])}</td>"
                     f"<td class='brk muted'>{e(c['rule_names'] or '—')}</td></tr>" for c in rv.coverage]))
    h.append("<h2>Log sources</h2>")
    h.append(_table(["Source", "Table", "State", "Last record", "GB a day", "Before", "Change", "Rules", "Owner"],
                    [f"<tr><td><b>{e(x['source'])}</b>{' <span class=muted>· critical</span>' if x['critical'] == 'yes' else ''}</td><td>{e(x['table'])}</td>"
                     f"<td>{_pill(x['state'])}</td><td class='num'>{e(x['last_record'] or '—')}</td><td class='num'>{x['gb_day']}</td><td class='num'>{x['gb_before']}</td>"
                     f"<td class='num'>{'' if x['change'] is None else str(x['change']) + ' %'}</td><td class='num'>{x['rules']}</td><td>{e(x['owner'])}</td></tr>"
                     for x in rv.sources], "No expected sources (sources.csv)."))
    h.append("<h2>Analytics rules</h2>")
    h.append(_table(["Rule", "Severity", "Techniques", "Tables", "State", "Incidents", "False or benign", "Findings"],
                    [f"<tr><td class='brk'><b>{e(r['rule'])}</b><br><span class='muted'>{e(r['kind'])} · {e(r['source'])}</span></td><td>{e(r['severity'])}</td>"
                     f"<td class='brk'>{e(r['techniques'] or '—')}</td><td class='brk'>{e(r['tables'] or '—')}</td><td>{_pill(r['state'])}</td>"
                     f"<td class='num'>{r['incidents']}</td><td class='num'>{_n(r['fp_rate'])}{' %' if r['fp_rate'] is not None else ''}</td>"
                     f"<td>{e(r['findings'])}</td></tr>" for r in sorted(rv.rules, key=lambda r: (r['state'] == 'working', r['state'] == 'disabled', r['rule']))]))
    h.append("<h2>Noise per rule</h2>")
    h.append(_table(["Rule", "Incidents", "True", "Benign", "False", "Undetermined", "Unclassified", "Open", "False or benign", "Median triage"],
                    [f"<tr><td class='brk'>{e(x['rule'])}</td><td class='num'>{x['incidents']}</td><td class='num'>{x['true_positive']}</td>"
                     f"<td class='num'>{x['benign_positive']}</td><td class='num'>{x['false_positive']}</td><td class='num'>{x['undetermined']}</td>"
                     f"<td class='num'>{x['unclassified']}</td><td class='num'>{x['open']}</td><td class='code'>{_bar(x['fp_rate'], 50, s.noisy_pct, x['true_positive'] + x['benign_positive'] + x['false_positive'] + x['undetermined'] >= s.noisy_min)}</td>"
                     f"<td class='num'>{_n(x['median_triage_h'])}{' h' if x['median_triage_h'] is not None else ''}</td></tr>" for x in rv.noise], "No incidents in the period."))
    h.append("<h2>Triage</h2>")
    h.append(_table(["Severity", "Incidents", "Triaged", "Median to triage", "Target", "Over target", "Of them nights or weekends", "Still open"],
                    [f"<tr><td><b>{e(x['severity'])}</b></td><td class='num'>{x['incidents']}</td><td class='num'>{x['triaged']}</td>"
                     f"<td class='num'>{_n(x['median_h'])} h</td><td class='num'>{_n(x['target_h'])} h</td><td class='num'>{x['over_target']}</td>"
                     f"<td class='num'>{x['off_hours']}</td><td class='num'>{x['open']}</td></tr>" for x in rv.triage], "No incidents in the period."))
    h.append("<footer class='muted'>A rule works when it is enabled, its last run did not fail and every table it reads is receiving data. "
             "A priority technique is covered when at least one working rule is mapped to it. False or benign: the share of classified incidents "
             "closed as false or benign positives. The priority techniques, limits and targets are this organisation's own choice (priorities.csv and "
             "settings.json).</footer></main></body></html>")
    return "\n".join(h)
