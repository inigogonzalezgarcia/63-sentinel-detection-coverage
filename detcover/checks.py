"""The review. First the log sources: an expected source that went silent, never arrived or dropped sharply, and big
tables that no rule reads. Then each analytics rule: blind because a table it reads is silent, failing in the health
log, disabled while it covers a priority technique, without an ATT&CK mapping or on an old template. Then the
organisation's priority techniques: covered by at least one rule that works today, covered only by broken rules, or not
covered at all. Then the incidents: rules whose incidents are nearly all false or benign positives, slow triage, High
incidents left open and incidents closed without a classification. Each finding has a severity, an owner and a due date;
a coverage score; decisions."""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta
from statistics import median

from .model import Data, Rule, covers

AREAS = {"sources": "Log sources", "rules": "Analytics rules", "coverage": "Technique coverage", "triage": "Incidents and noise"}
SEV = {"RED": 0, "AMBER": 1}
NO_TABLES = ("fusion", "microsoftsecurityincidentcreation", "threatintelligence", "mlbehavioranalytics")


@dataclass
class Finding:
    code: str
    severity: str
    area: str
    subject: str
    text: str
    owner: str = ""
    due: datetime | None = None
    action: str = ""


@dataclass
class Review:
    findings: list[Finding] = field(default_factory=list)
    sources: list[dict] = field(default_factory=list)
    tables: dict = field(default_factory=dict)          # table -> {"state", "last", "hours", "gb", "before", "change", "rules"}
    rules: list[dict] = field(default_factory=list)
    coverage: list[dict] = field(default_factory=list)
    noise: list[dict] = field(default_factory=list)
    triage: list[dict] = field(default_factory=list)
    decisions: list[dict] = field(default_factory=list)
    start: datetime | None = None
    score: float = 0.0
    high_score: float = 0.0
    status: str = "GREEN"


def pl(n: int, word: str, plural: str | None = None) -> str:
    return f"{n:g} {word if n == 1 else plural or word + 's'}"


def _h(x: float) -> str:
    return f"{x:.0f} h" if x < 72 else f"{x / 24:.0f} days"


def _list(xs, n: int = 6) -> str:
    xs = list(xs)
    return ", ".join(xs[:n]) + (f" and {len(xs) - n} more" if len(xs) > n else "")


def reads_tables(r: Rule) -> bool:
    return bool(r.tables) and r.kind.lower().replace(" ", "") not in NO_TABLES


def review(d: Data) -> Review:
    s, own = d.settings, d.settings.owners
    rv = Review()
    rv.start = s.review - timedelta(days=s.days)
    today = s.review.date()

    def add(f: Finding):
        f.due = f.due or datetime.combine(today + timedelta(days=7 if f.severity == "RED" else 28), time(17, 0))
        rv.findings.append(f)

    enabled = [r for r in d.rules if r.enabled]
    readers = defaultdict(list)                          # table (lower) -> enabled rules that read it
    for r in enabled:
        if reads_tables(r):
            for t in r.tables:
                readers[t.lower()].append(r.name)

    # --- tables: last record, volume last week against the weeks before, state
    delay = {}
    for x in d.sources_expected:
        k = x.table.lower()
        delay[k] = min(delay.get(k, 1e9), x.delay or s.silent_hours)
    names = {}
    for t in [x.table for x in d.sources_expected] + [t for r in d.rules if reads_tables(r) for t in r.tables] + list(d.last_record) + list(d.ingestion):
        names.setdefault(t.lower(), t)
    last_l = {k.lower(): v for k, v in d.last_record.items()}
    ing_l = defaultdict(dict)
    for k, v in d.ingestion.items():
        for dd, gb in v.items():
            ing_l[k.lower()][dd] = ing_l[k.lower()].get(dd, 0.0) + gb
    week = [today - timedelta(days=i) for i in range(1, 8)]
    before = [today - timedelta(days=i) for i in range(8, s.days + 1)]
    for k, t in names.items():
        days = ing_l.get(k, {})
        last = last_l.get(k)
        if last is None and any(v > 0 for v in days.values()):
            last = datetime.combine(max(dd for dd, v in days.items() if v > 0), time(23, 59))
        gb = round(sum(days.get(x, 0.0) for x in week) / 7, 2) if days else 0.0
        prior = [days.get(x, 0.0) for x in before]
        gb_before = round(sum(prior) / len(prior), 2) if days and prior else 0.0
        change = round(100 * (gb - gb_before) / gb_before) if gb_before else None
        hours = round((s.review - last).total_seconds() / 3600, 1) if last else None
        limit = delay.get(k, s.silent_hours)
        st = "missing" if last is None else "silent" if hours > limit else "drop" if change is not None and change <= -s.drop_pct else "live"
        rv.tables[k] = {"table": t, "state": st, "last": last, "hours": hours, "limit": limit, "gb": gb, "before": gb_before, "change": change,
                        "rules": sorted(readers.get(k, []))}

    def live(t: str) -> bool:
        return rv.tables.get(t.lower(), {"state": "missing"})["state"] in ("live", "drop")

    # --- log sources the organisation expects
    for x in d.sources_expected:
        tb = rv.tables[x.table.lower()]
        rv.sources.append({"source": x.name, "table": x.table, "owner": x.owner or own["platform"], "critical": "yes" if x.critical else "no",
                           "state": tb["state"], "last_record": tb["last"].strftime("%Y-%m-%d %H:%M") if tb["last"] else "", "hours": tb["hours"],
                           "gb_day": tb["gb"], "gb_before": tb["before"], "change": tb["change"], "rules": len(tb["rules"])})
        who = x.owner or own["platform"]
        n = len(tb["rules"])
        if tb["state"] == "silent":
            add(Finding("SOURCE-SILENT", "RED" if x.critical else "AMBER", "sources", x.name,
                        f"Nothing in {x.table} since {tb['last']:%a %d %b %H:%M} ({_h(tb['hours'])}, limit {_h(tb['limit'])}); {pl(n, 'enabled rule')} read it",
                        who, datetime.combine(today, time(17, 0)) if x.critical else None,
                        "Check the connector, the collector and the forwarder; once data arrives, run the rules that read it over the gap"))
        elif tb["state"] == "missing":
            add(Finding("SOURCE-MISSING", "RED" if x.critical else "AMBER", "sources", x.name,
                        f"{x.table} has never received data in this workspace" + (f"; {pl(n, 'enabled rule')} read it" if n else ""), who, None,
                        "Connect the source or take it off the expected list with a reason"))
        elif tb["state"] == "drop":
            add(Finding("SOURCE-DROP", "AMBER", "sources", x.name,
                        f"{x.table}: {tb['gb']} GB a day last week against {tb['before']} GB before ({tb['change']} %)", who, None,
                        "Find which devices stopped sending (a filter, an agent, a collector change) and bring them back"))
    expected = {x.table.lower() for x in d.sources_expected}
    for k, tb in sorted(rv.tables.items(), key=lambda kv: -kv[1]["gb"]):
        if k not in expected and tb["state"] in ("live", "drop") and tb["gb"] >= s.unused_gb and not tb["rules"]:
            add(Finding("TABLE-NO-RULES", "AMBER", "sources", tb["table"],
                        f"{tb['gb']} GB a day and no enabled rule reads it", own["platform"], None,
                        "Decide: keep it for hunting and investigation, move it to a lower-cost table plan, or stop collecting it"))

    # --- analytics rules
    prio = {p.technique for p in d.priorities}
    period = [h for h in d.health if rv.start <= h.time <= s.review]
    hr = defaultdict(list)
    for h in period:
        hr[h.rule.lower()].append(h)
    inc = [i for i in d.incidents if i.created and rv.start <= i.created <= s.review]
    by_rule = defaultdict(list)
    for i in inc:
        by_rule[i.rule.lower()].append(i)
    state = {}
    blind_by = defaultdict(lambda: {"full": [], "part": []})   # table -> rules that it blinds completely or in part
    for r in d.rules:
        hs = hr.get(r.name.lower(), [])
        fails = [h for h in hs if h.status.lower().startswith("fail")]
        last_fail = bool(hs) and hs[-1].status.lower().startswith("fail")
        down = [t for t in r.tables if not live(t)] if reads_tables(r) else []
        if not r.enabled:
            st = "disabled"
        elif last_fail:
            st = "failing"
        elif down and len(down) == len(r.tables):
            st = "blind"
        elif down:
            st = "partly blind"
        else:
            st = "working"
        state[r.name] = st
        mapped = [t for t in r.techniques if any(covers(t, p) for p in prio)]
        if r.enabled and last_fail:
            run = [h for h in reversed(hs) if h.status.lower().startswith("fail")]
            k = 0
            for h in reversed(hs):
                if not h.status.lower().startswith("fail"):
                    break
                k += 1
            since = hs[-k].time
            add(Finding("RULE-FAILING", "RED", "rules", r.name,
                        f"Failing since {since:%a %d %b} ({pl(k, 'run')} in a row): {run[0].reason or 'no reason given'}", own["engineering"], None,
                        "Fix the query (time-outs, a renamed column, a missing watchlist) and check that it runs again"))
        elif r.enabled and fails:
            add(Finding("RULE-FAILING", "AMBER", "rules", r.name,
                        f"Failed {pl(len(fails), 'time')} in the period, last on {fails[-1].time:%a %d %b}: {fails[-1].reason or 'no reason given'}",
                        own["engineering"], None, "Find out why it fails now and then and fix it before it stops for good"))
        if r.enabled and not last_fail and down:
            for t in down:
                blind_by[t.lower()]["full" if st == "blind" else "part"].append(r.name)
        if not r.enabled and mapped:
            add(Finding("RULE-DISABLED", "AMBER", "rules", r.name,
                        f"Disabled{f' since {r.modified:%d %b %Y}' if r.modified else ''}, and it covers the priority {'technique' if len(mapped) == 1 else 'techniques'} {_list(mapped)}",
                        own["engineering"], None, "Switch it back on, or write down why it stays off and what covers the technique instead"))
        ns = by_rule.get(r.name.lower(), [])
        cls = Counter(i.classification for i in ns if not i.is_open and i.classification)
        classified = sum(cls.values())
        fpr = round(100 * (cls["FalsePositive"] + cls["BenignPositive"]) / classified, 1) if classified else None
        rv.rules.append({"rule": r.name, "kind": r.kind, "enabled": "yes" if r.enabled else "no", "severity": r.severity, "source": r.source,
                         "tactics": "; ".join(r.tactics), "techniques": "; ".join(r.techniques), "tables": "; ".join(r.tables), "state": st,
                         "failures": len(fails), "incidents": len(ns), "true_positive": cls["TruePositive"], "fp_rate": fpr,
                         "version": r.version, "latest": r.latest})
        if r.enabled and fpr is not None and classified >= s.noisy_min and fpr >= s.noisy_pct:
            add(Finding("RULE-NOISY", "AMBER", "triage", r.name,
                        f"{pl(len(ns), 'incident')} in the period; {fpr} % of the classified ones were false or benign positives ({cls['TruePositive']} true)",
                        own["soc"], None, "Tune it with the SOC: exclusions with an owner and an end date, a higher threshold or a narrower scope"))
    for k, b in blind_by.items():
        tb = rv.tables.get(k, {"table": k, "state": "missing"})
        if b["full"]:
            add(Finding("RULE-BLIND", "RED", "rules", tb["table"],
                        f"{pl(len(b['full']), 'enabled rule')} read only {tb['table']} ({tb['state']}) and cannot fire: {_list(sorted(b['full']))}",
                        own["engineering"], None, "Get the source back (see Log sources); if it is gone for good, point the rules at a table that has the data or retire them"))
        if b["part"]:
            add(Finding("RULE-BLIND", "AMBER", "rules", tb["table"] + " (in part)",
                        f"{pl(len(b['part']), 'enabled rule')} also read {tb['table']} ({tb['state']}), so part of what they look for cannot show up: {_list(sorted(b['part']))}",
                        own["engineering"], None, "Get the source back; until then the rules only see the other tables"))
    nomap = [r.name for r in enabled if r.kind.lower() in ("scheduled", "nrt") and not r.techniques]
    if nomap:
        add(Finding("RULE-NO-MAPPING", "AMBER", "rules", "ATT&CK mapping",
                    f"{pl(len(nomap), 'enabled rule')} with no ATT&CK technique, so they count for nothing in coverage: {_list(nomap)}",
                    own["engineering"], None, "Map each one to the techniques it detects"))
    old = [r for r in enabled if r.outdated]
    if old:
        add(Finding("RULE-OUTDATED", "AMBER", "rules", "Templates",
                    f"{pl(len(old), 'rule')} on an older version of their template: " + _list(f"{r.name} ({r.version} → {r.latest})" for r in old),
                    own["engineering"], None, "Compare each with the new template version and update it, keeping your own changes"))

    # --- priority techniques
    working = 0
    high = [p for p in d.priorities if p.priority == "high"]
    high_ok = 0
    for p in d.priorities:
        rs = [r for r in d.rules if any(covers(t, p.technique) for t in r.techniques)]
        en = [r for r in rs if r.enabled]
        ok = [r for r in en if state[r.name] == "working"]
        st = "covered" if ok else "broken" if en else "disabled only" if rs else "none"
        working += bool(ok)
        high_ok += bool(ok) and p.priority == "high"
        rv.coverage.append({"technique": p.technique, "name": p.name, "tactic": p.tactic, "priority": p.priority, "rules": len(rs), "enabled": len(en),
                            "working": len(ok), "status": st, "rule_names": "; ".join(r.name for r in rs), "why": p.why})
        sev = "RED" if p.priority == "high" else "AMBER"
        label = f"{p.technique} {p.name}".strip()
        if not en:
            dis = [r.name for r in rs]
            add(Finding("GAP-NONE", sev, "coverage", label,
                        f"No enabled rule detects it ({p.priority} priority)" + (f"; disabled: {_list(dis)}" if dis else ""), own["engineering"], None,
                        ("Switch the disabled rule back on" if dis else "Install a template or write a rule for it") + ", then test it with a safe simulation"))
        elif not ok:
            add(Finding("GAP-BROKEN", sev, "coverage", label,
                        f"Every rule that detects it is broken today ({p.priority} priority): " + _list(f"{r.name} ({state[r.name]})" for r in en),
                        own["engineering"], None, "Fix the rules (see Analytics rules); until then, hunt for it by hand"))
    rv.score = round(100 * working / len(d.priorities), 1) if d.priorities else 100.0
    rv.high_score = round(100 * high_ok / len(high), 1) if high else 100.0

    # --- incidents: noise table, triage time, open and unclassified
    for name, ns in sorted(by_rule.items(), key=lambda kv: -len(kv[1])):
        cls = Counter(i.classification or ("open" if i.is_open else "unclassified") for i in ns)
        tri = [(i.first - i.created).total_seconds() / 3600 for i in ns if i.first]
        classified = cls["TruePositive"] + cls["FalsePositive"] + cls["BenignPositive"] + cls["Undetermined"]
        rv.noise.append({"rule": ns[0].rule, "incidents": len(ns), "true_positive": cls["TruePositive"], "benign_positive": cls["BenignPositive"],
                         "false_positive": cls["FalsePositive"], "undetermined": cls["Undetermined"], "unclassified": cls["unclassified"], "open": cls["open"],
                         "fp_rate": round(100 * (cls["FalsePositive"] + cls["BenignPositive"]) / classified, 1) if classified else None,
                         "median_triage_h": round(median(tri), 1) if tri else None})
    for sev in ("High", "Medium", "Low"):
        xs = [i for i in inc if i.severity == sev]
        if not xs:
            continue
        tri = [(i, (i.first - i.created).total_seconds() / 3600) for i in xs if i.first]
        target = s.triage_hours.get(sev)
        late = [i for i, t in tri if target and t > target]
        off = sum(1 for i in late if i.created.weekday() >= 5 or not 7 <= i.created.hour < 20)
        md = round(median(t for _, t in tri), 1) if tri else None
        rv.triage.append({"severity": sev, "incidents": len(xs), "triaged": len(tri), "median_h": md, "target_h": target, "over_target": len(late),
                          "off_hours": off, "open": sum(i.is_open for i in xs)})
        if target and tri and sev in ("High", "Medium") and ((md or 0) > target or 100 * len(late) / len(tri) > s.late_pct):
            add(Finding("TRIAGE-SLOW", "AMBER", "triage", f"{sev} incidents",
                        f"{len(late)} of {len(tri)} took longer than the {target} h target to triage (median {md} h); {off} of the late ones arrived at night or at the weekend",
                        own["soc"], None, "Look at the rota and the routing for nights and weekends, or an automation rule that assigns them as they arrive"))
    old_open = [i for i in d.incidents if i.is_open and i.severity == "High" and i.created and (s.review - i.created).days > s.open_days]
    if old_open:
        unassigned = sum(1 for i in old_open if not i.owner)
        add(Finding("TRIAGE-OPEN", "RED", "triage", "High incidents",
                    f"{pl(len(old_open), 'High incident')} open for more than {s.open_days} days ({unassigned} unassigned): "
                    + _list(f"#{i.id} {i.title}" for i in old_open), own["soc"], datetime.combine(today, time(17, 0)),
                    "Assign each one today and close it or escalate it"))
    closed = [i for i in inc if not i.is_open]
    uncl = [i for i in closed if not i.classification]
    if closed and 100 * len(uncl) / len(closed) > s.unclassified_pct:
        add(Finding("UNCLASSIFIED", "AMBER", "triage", "Classification",
                    f"{len(uncl)} of {len(closed)} closed incidents ({round(100 * len(uncl) / len(closed))} %) have no classification, so the noise of their rules cannot be measured",
                    own["soc"], None, "Make the classification required when closing an incident"))

    # --- decisions
    def dec(t, detail, owner, due):
        rv.decisions.append({"decision": t, "detail": detail, "owner": owner, "due": due})
    soon = datetime.combine(today + timedelta(days=7), time(17, 0))
    down = [x for x in d.sources_expected if rv.tables[x.table.lower()]["state"] in ("silent", "missing")]
    crit = [x for x in down if x.critical]
    if crit:
        blind = sorted({r for x in crit for r in rv.tables[x.table.lower()]["rules"]})
        dec("Get the critical source back today and run its rules over the gap" if len(crit) == 1 else
            f"Get the {len(crit)} critical sources back today and run their rules over the gap",
            _list(x.name for x in crit) + (f"; {pl(len(blind), 'rule')} cannot fire until then" if blind else ""), own["platform"], datetime.combine(today, time(17, 0)))
    other = [x for x in down if not x.critical and rv.tables[x.table.lower()]["rules"]]
    if other:
        dec("Connect or drop an expected source that rules depend on" if len(other) == 1 else f"Connect or drop {len(other)} expected sources that rules depend on",
            "; ".join(f"{x.name}: {pl(len(rv.tables[x.table.lower()]['rules']), 'rule')} wait for it" for x in other), own["platform"], soon + timedelta(days=14))
    gaps = [f for f in rv.findings if f.code in ("GAP-NONE", "GAP-BROKEN") and f.severity == "RED"]
    if gaps:
        dec(f"Close the {pl(len(gaps), 'gap')} on high-priority techniques", _list(f.subject for f in gaps), own["engineering"], soon + timedelta(days=14))
    rep = [f for f in rv.findings if f.code in ("RULE-FAILING", "RULE-DISABLED")]
    if rep:
        dec(f"Repair {pl(len({f.subject for f in rep}), 'rule')} that fail or are switched off", _list(sorted({f.subject for f in rep})), own["engineering"], soon)
    noisy = sorted([x for x in rv.rules if any(f.code == "RULE-NOISY" and f.subject == x["rule"] for f in rv.findings)], key=lambda x: -x["incidents"])
    if noisy:
        dec(f"Tune the {pl(len(noisy), 'noisiest rule')}", _list(f"{x['rule']} ({x['incidents']} incidents, {x['fp_rate']} % false or benign)" for x in noisy),
            own["soc"], soon + timedelta(days=7))
    tri = [f for f in rv.findings if f.code in ("TRIAGE-OPEN", "TRIAGE-SLOW", "UNCLASSIFIED")]
    if tri:
        dec("Fix triage: assign the old High incidents, review the rota and make classification required", "; ".join(f.text for f in tri),
            own["soc"], soon)
    unused = [f for f in rv.findings if f.code == "TABLE-NO-RULES"]
    if unused:
        dec(f"Decide on {pl(len(unused), 'table')} that no rule reads", _list(f"{f.subject} ({f.text.split(' GB')[0]} GB a day)" for f in unused),
            own["platform"], soon + timedelta(days=21))

    red = any(f.severity == "RED" for f in rv.findings)
    amber = any(f.severity == "AMBER" for f in rv.findings)
    rv.status = "RED" if red or rv.score < s.score_red else "AMBER" if amber or rv.score < s.score_amber else "GREEN"
    for x in rv.rules:
        x["findings"] = " ".join(sorted({f.code for f in rv.findings if f.subject == x["rule"]}))
    rv.findings.sort(key=lambda f: (SEV[f.severity], list(AREAS).index(f.area), f.code, f.subject))
    return rv


def summary(d: Data, rv: Review) -> dict:
    states = Counter(x["state"] for x in rv.rules)
    srcs = Counter(x["state"] for x in rv.sources)
    inc = [i for i in d.incidents if i.created and rv.start <= i.created <= d.settings.review]
    return {"status": rv.status, "score": rv.score, "high_score": rv.high_score, "previous": d.settings.previous_score,
            "priorities": len(d.priorities), "covered": sum(c["status"] == "covered" for c in rv.coverage),
            "high": sum(p.priority == "high" for p in d.priorities), "high_covered": sum(c["status"] == "covered" and c["priority"] == "high" for c in rv.coverage),
            "rules": len(d.rules), "enabled": sum(r.enabled for r in d.rules), "working": states["working"],
            "broken": states["failing"] + states["blind"] + states["partly blind"], "sources": len(rv.sources),
            "sources_down": srcs["silent"] + srcs["missing"], "incidents": len(inc),
            "red": sum(1 for f in rv.findings if f.severity == "RED"), "amber": sum(1 for f in rv.findings if f.severity == "AMBER"),
            "decisions": len(rv.decisions)}
