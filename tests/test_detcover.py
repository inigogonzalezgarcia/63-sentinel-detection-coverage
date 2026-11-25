import csv
import hashlib
import json
from pathlib import Path

from detcover import simulate
from detcover.checks import review
from detcover.cli import OUTPUTS, run
from detcover.model import covers, load, technique

RH = ["Rule", "Kind", "Enabled", "Severity", "Tactics", "Techniques", "Tables", "Frequency", "Source", "TemplateVersion", "LatestVersion", "Modified"]
PH = ["Technique", "Name", "Tactic", "Priority", "Why"]
REVIEW = "2026-11-25 09:00:00"


def rule(name, tech="T1078", tables="SigninLogs", enabled="yes", kind="Scheduled", version="", latest="", modified="2026-01-01"):
    return [name, kind, enabled, "High", "InitialAccess", tech, tables, "PT1H", "Custom", version, latest, modified]


def write(folder: Path, rules, priorities=(("T1078", "Valid Accounts", "Initial Access", "high", ""),), sources=None, tables=None, ingestion=None,
          incidents=None, health=None, settings=None) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    files = [("rules.csv", RH, rules), ("priorities.csv", PH, priorities)]
    if sources is not None:
        files.append(("sources.csv", ["Source", "Table", "Owner", "Critical", "MaxDelayHours"], sources))
    files.append(("tables.csv", ["Table", "LastRecord"], tables if tables is not None else [["SigninLogs", "2026-11-25 08:50:00"]]))
    if ingestion is not None:
        files.append(("ingestion.csv", ["Date", "Table", "GB"], ingestion))
    if incidents is not None:
        files.append(("incidents.csv", ["Incident", "Title", "Rule", "Severity", "Status", "Classification", "Owner", "Created", "FirstModified", "Closed"], incidents))
    if health is not None:
        files.append(("health.csv", ["Time", "Rule", "Status", "Reason"], health))
    for name, header, rows in files:
        with (folder / name).open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(header)
            w.writerows(rows)
    (folder / "settings.json").write_text(json.dumps({"organisation": "Test", "review": REVIEW, **(settings or {})}), encoding="utf-8")
    return folder


def codes(folder: Path) -> set:
    return {f.code for f in review(load(folder)).findings}


def test_technique_parsing_and_cover():
    assert technique("t1059/001 - PowerShell") == "T1059.001"
    assert technique("T1078") == "T1078"
    assert technique("Valid accounts") == ""
    assert covers("T1110", "T1110.003") and covers("T1110.003", "T1110") and covers("T1078", "T1078")
    assert not covers("T1110.001", "T1110.003") and not covers("T1003", "T1004")


def test_clean_workspace_is_green(tmp_path):
    d = write(tmp_path, [rule("Sign-in from a new country")], sources=[["Entra ID sign-ins", "SigninLogs", "Identity", "yes", 6]])
    rv = review(load(d))
    assert rv.findings == [] and rv.score == 100.0 and rv.status == "GREEN"
    assert rv.coverage[0]["status"] == "covered"


def test_silent_critical_source_blinds_its_rules(tmp_path):
    d = write(tmp_path, [rule("Firewall beacon", "T1071", "CommonSecurityLog")], priorities=[["T1071", "Application Layer Protocol", "C2", "high", ""]],
              sources=[["Firewalls", "CommonSecurityLog", "Network", "yes", 6]], tables=[["CommonSecurityLog", "2026-11-20 14:00:00"]])
    rv = review(load(d))
    got = {(f.code, f.severity) for f in rv.findings}
    assert ("SOURCE-SILENT", "RED") in got and ("RULE-BLIND", "RED") in got and ("GAP-BROKEN", "RED") in got
    assert rv.score == 0.0 and rv.status == "RED"
    assert rv.decisions[0]["decision"].startswith("Get the critical source back today")


def test_missing_source_and_partly_blind_rule(tmp_path):
    d = write(tmp_path, [rule("Download then upload", "T1567", "OfficeActivity;CommonSecurityLog")],
              priorities=[["T1567", "Exfiltration Over Web Service", "Exfiltration", "medium", ""]],
              sources=[["Firewalls", "CommonSecurityLog", "Network", "no", 24]], tables=[["OfficeActivity", "2026-11-25 08:00:00"]])
    rv = review(load(d))
    got = {(f.code, f.severity, f.subject) for f in rv.findings}
    assert ("SOURCE-MISSING", "AMBER", "Firewalls") in got
    assert ("RULE-BLIND", "AMBER", "CommonSecurityLog (in part)") in got
    assert ("GAP-BROKEN", "AMBER", "T1567 Exfiltration Over Web Service") in got


def test_volume_drop(tmp_path):
    days = [f"2026-11-{x:02d}" for x in range(1, 25)] + [f"2026-10-{x:02d}" for x in range(26, 32)]
    ing = [[dd, "Syslog", 1.0 if dd >= "2026-11-18" else 5.0] for dd in days]
    d = write(tmp_path, [rule("Sudo", "T1078", "Syslog")], sources=[["Linux", "Syslog", "Linux", "no", 24]], tables=[["Syslog", "2026-11-25 08:00:00"]],
              ingestion=ing)
    rv = review(load(d))
    f = [f for f in rv.findings if f.code == "SOURCE-DROP"]
    assert f and "-80 %" in f[0].text
    assert rv.coverage[0]["status"] == "covered"     # a drop does not blind the rule


def test_big_table_with_no_rule(tmp_path):
    ing = [[f"2026-11-{x:02d}", "AzureDiagnostics", 8.0] for x in range(1, 25)] + [[f"2026-11-{x:02d}", "Heartbeat", 0.2] for x in range(1, 25)]
    d = write(tmp_path, [rule("Sign-in")], ingestion=ing)
    subjects = {f.subject for f in review(load(d)).findings if f.code == "TABLE-NO-RULES"}
    assert subjects == {"AzureDiagnostics"}


def test_failing_rule_red_and_flaky_rule_amber(tmp_path):
    h = [["2026-11-20 10:00:00", "Kerb", "Success", ""], ["2026-11-21 10:00:00", "Kerb", "Failure", "time limit"], ["2026-11-22 10:00:00", "Kerb", "Failure", "time limit"],
         ["2026-11-10 10:00:00", "Travel", "Failure", "throttled"], ["2026-11-25 08:00:00", "Travel", "Success", ""]]
    d = write(tmp_path, [rule("Kerb", "T1558.003", "SigninLogs"), rule("Travel")], priorities=[["T1558.003", "Kerberoasting", "Credential Access", "high", ""]],
              health=h)
    rv = review(load(d))
    sev = {f.subject: f.severity for f in rv.findings if f.code == "RULE-FAILING"}
    assert sev == {"Kerb": "RED", "Travel": "AMBER"}
    assert "2 runs in a row" in [f.text for f in rv.findings if f.subject == "Kerb"][0]
    assert {f.code for f in rv.findings if f.subject.startswith("T1558.003")} == {"GAP-BROKEN"}


def test_disabled_rule_on_a_priority_technique(tmp_path):
    d = write(tmp_path, [rule("Shadow copies deleted", "T1490", "SigninLogs", enabled="no", modified="2026-09-14")],
              priorities=[["T1490", "Inhibit System Recovery", "Impact", "high", ""]])
    rv = review(load(d))
    gap = [f for f in rv.findings if f.code == "GAP-NONE"][0]
    assert gap.severity == "RED" and "disabled: Shadow copies deleted" in gap.text
    assert "since 14 Sep 2026" in [f.text for f in rv.findings if f.code == "RULE-DISABLED"][0]
    assert rv.coverage[0]["status"] == "disabled only"


def test_unmapped_and_outdated_rules(tmp_path):
    d = write(tmp_path, [rule("Mapped"), rule("Admin at night", ""), rule("Old template", "T1078", version="1.2.0", latest="1.10.0"),
                         rule("Fusion", "", "", kind="Fusion")])
    rv = review(load(d))
    nomap = [f for f in rv.findings if f.code == "RULE-NO-MAPPING"][0]
    assert "Admin at night" in nomap.text and "Fusion" not in nomap.text
    assert "1.2.0 → 1.10.0" in [f.text for f in rv.findings if f.code == "RULE-OUTDATED"][0]


def test_noisy_rule_needs_enough_classified_incidents(tmp_path):
    inc = []
    for n in range(12):
        inc.append([n, "Country", "Country", "Medium", "Closed", "BenignPositive" if n < 11 else "TruePositive", "ana", f"2026-11-{n + 2:02d} 10:00:00",
                    f"2026-11-{n + 2:02d} 11:00:00", f"2026-11-{n + 2:02d} 12:00:00"])
    for n in range(5):
        inc.append([100 + n, "Rare", "Rare", "Medium", "Closed", "FalsePositive", "ana", f"2026-11-{n + 2:02d} 10:00:00", f"2026-11-{n + 2:02d} 11:00:00",
                    f"2026-11-{n + 2:02d} 12:00:00"])
    d = write(tmp_path, [rule("Country"), rule("Rare")], incidents=inc)
    rv = review(load(d))
    assert [f.subject for f in rv.findings if f.code == "RULE-NOISY"] == ["Country"]
    assert [x for x in rv.noise if x["rule"] == "Country"][0]["fp_rate"] == 91.7


def test_triage_late_at_night_and_old_open_high(tmp_path):
    inc = [[1, "Spray", "Spray", "High", "New", "", "", "2026-11-10 23:00:00", "", ""]]
    for n in range(10):   # half of them late, all of those at night
        late = n % 2 == 0
        c = f"2026-11-{n + 11:02d} {'02' if late else '10'}:00:00"
        inc.append([10 + n, "Spray", "Spray", "High", "Closed", "TruePositive", "ana", c, f"2026-11-{n + 11:02d} {'09' if late else '11'}:00:00",
                    f"2026-11-{n + 11:02d} 12:00:00"])
    d = write(tmp_path, [rule("Spray")], incidents=inc)
    rv = review(load(d))
    slow = [f for f in rv.findings if f.code == "TRIAGE-SLOW"][0]
    assert slow.text.startswith("5 of 10 took longer than the 4 h target") and "5 of the late ones arrived at night" in slow.text
    old = [f for f in rv.findings if f.code == "TRIAGE-OPEN"][0]
    assert old.severity == "RED" and "1 unassigned" in old.text


def test_unclassified_closed_incidents(tmp_path):
    inc = [[n, "R", "R", "Low", "Closed", "" if n < 4 else "TruePositive", "ana", "2026-11-20 10:00:00", "2026-11-20 11:00:00", "2026-11-20 12:00:00"]
           for n in range(10)]
    d = write(tmp_path, [rule("R")], incidents=inc)
    assert "UNCLASSIFIED" in codes(d)


def test_other_column_names_semicolons_and_missing_files(tmp_path):
    (tmp_path / "rules.csv").write_text("DisplayName;Enabled;Techniques;DataTypes\nSpray;True;T1110.003|T1078;SigninLogs\n", encoding="utf-8")
    (tmp_path / "priorities.csv").write_text("TechniqueId,Name,Priority\nT1110.003,Password Spraying,High\n", encoding="utf-8")
    d = load(tmp_path)
    assert d.rules[0].techniques == ["T1110.003", "T1078"] and d.priorities[0].priority == "high"
    rv = review(d)
    assert {f.code for f in rv.findings} == {"RULE-BLIND", "GAP-BROKEN"}   # no tables.csv: nothing is known to arrive
    (tmp_path / "priorities.csv").unlink()
    try:
        load(tmp_path)
        assert False
    except FileNotFoundError as exc:
        assert "priorities.csv" in str(exc)


def test_demo_end_to_end(tmp_path):
    sm = run(simulate.write(tmp_path / "data"), tmp_path / "out")
    for name in OUTPUTS:
        assert (tmp_path / "out" / name).exists()
    assert sm["status"] == "RED" and sm["score"] == 63.6 and sm["high_score"] == 66.7
    assert (sm["covered"], sm["priorities"], sm["working"], sm["enabled"], sm["sources_down"]) == (14, 22, 26, 36, 2)
    assert (sm["red"], sm["amber"], sm["decisions"]) == (9, 19, 7)
    pack = (tmp_path / "out" / "detection-pack.md").read_text(encoding="utf-8")
    assert "Firewalls (CEF); 7 rules cannot fire until then" in pack and "T1114.003 Email Forwarding Rule" in pack


def test_demo_incidents_follow_the_sources(tmp_path):
    d = load(simulate.write(tmp_path))
    fw = {r.name for r in d.rules if "CommonSecurityLog" in r.tables}
    assert fw and not [i for i in d.incidents if i.rule in fw and i.created >= simulate.FW_SILENT]
    assert not [i for i in d.incidents if i.rule.startswith("Kerberoasting") and i.created >= simulate.KERB_FAIL]
    assert not [i for i in d.incidents if i.rule.startswith("AWS")]


def test_demo_is_deterministic(tmp_path):
    a, b = simulate.write(tmp_path / "a"), simulate.write(tmp_path / "b")
    for f in sorted(a.iterdir()):
        assert hashlib.sha256(f.read_bytes()).digest() == hashlib.sha256((b / f.name).read_bytes()).digest(), f.name
