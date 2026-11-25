"""Loading: the analytics rules of the Microsoft Sentinel workspace (rules.csv, one row per rule with its MITRE ATT&CK
mapping and the tables its query reads), the log sources the organisation expects (sources.csv), the last record of each
table (tables.csv), daily ingestion per table (ingestion.csv), the incidents of the period (incidents.csv), rule health
(health.csv), the organisation's priority techniques (priorities.csv) and the review settings (settings.json). Forgiving
column names, into plain dataclasses. rules.csv and priorities.csv are required."""
from __future__ import annotations

import csv
import json
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

RULE_ALIASES = {
    "name": ["Rule", "DisplayName", "Name", "Analytic rule"],
    "kind": ["Kind", "Type", "RuleType"],
    "enabled": ["Enabled", "Status", "State"],
    "severity": ["Severity"],
    "tactics": ["Tactics"],
    "techniques": ["Techniques", "Technique", "MitreTechniques"],
    "tables": ["Tables", "DataTypes", "Data sources", "DataSources"],
    "frequency": ["Frequency", "QueryFrequency", "Run every"],
    "source": ["Source", "Origin"],
    "version": ["TemplateVersion", "Version", "Installed version"],
    "latest": ["LatestVersion", "Latest version", "AvailableVersion"],
    "modified": ["Modified", "LastModifiedUtc", "LastModified"],
}
SOURCE_ALIASES = {
    "name": ["Source", "Name", "Log source"],
    "table": ["Table", "DataType"],
    "owner": ["Owner"],
    "critical": ["Critical"],
    "delay": ["MaxDelayHours", "Max delay hours", "MaxDelay"],
}
TABLE_ALIASES = {"table": ["Table", "DataType", "Type"], "last": ["LastRecord", "Last record", "LastTimeGenerated", "max_TimeGenerated"]}
INGEST_ALIASES = {"date": ["Date", "Day", "TimeGenerated"], "table": ["Table", "DataType"], "gb": ["GB", "Gigabytes", "SizeGB"]}
INCIDENT_ALIASES = {
    "id": ["Incident", "IncidentNumber", "Number", "Id"],
    "title": ["Title"],
    "rule": ["Rule", "AnalyticRule", "RuleName", "Rules"],
    "severity": ["Severity"],
    "status": ["Status"],
    "classification": ["Classification"],
    "owner": ["Owner", "AssignedTo"],
    "created": ["Created", "CreatedTime"],
    "first": ["FirstModified", "FirstModifiedTime", "Triaged"],
    "closed": ["Closed", "ClosedTime"],
}
HEALTH_ALIASES = {"time": ["Time", "TimeGenerated"], "rule": ["Rule", "SentinelResourceName", "Name"], "status": ["Status"],
                  "reason": ["Reason", "Description"]}
PRIORITY_ALIASES = {"technique": ["Technique", "TechniqueId", "Id"], "name": ["Name", "Technique name"], "tactic": ["Tactic", "Tactics"],
                    "priority": ["Priority"], "why": ["Why", "Reason", "Notes"]}
FILES = {"rules.csv": "Analytics rules", "priorities.csv": "Priority techniques", "sources.csv": "Expected log sources", "tables.csv": "Tables",
         "ingestion.csv": "Daily ingestion", "incidents.csv": "Incidents", "health.csv": "Rule health"}


def _norm(s) -> str:
    s = unicodedata.normalize("NFKD", str(s or "")).encode("ascii", "ignore").decode().lower()
    return re.sub(r"\s+", " ", s).strip()


def yes(v) -> bool:
    return _norm(v) in {"yes", "y", "true", "1", "x", "enabled", "on"}


def parse_dt(v) -> datetime | None:
    s = str(v or "").strip().replace("Z", "")
    if "." in s and "T" in s:
        s = s.split(".")[0]
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%Y-%m-%d", "%d/%m/%Y"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    return None


def items(v) -> list[str]:
    return [x.strip() for x in re.split(r"[;|,]", str(v or "")) if x.strip()]


def number(v, default: float = 0.0) -> float:
    try:
        return float(str(v).replace(",", ".")) if str(v or "").strip() else default
    except ValueError:
        return default


def technique(v: str) -> str:
    """T1059.001, t1059/001 or 'T1059.001 - PowerShell' -> T1059.001; anything else -> ''."""
    m = re.search(r"\bT(\d{4})(?:[./](\d{3}))?\b", str(v or "").upper())
    return "" if not m else f"T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "")


def covers(rule_t: str, wanted: str) -> bool:
    """A rule mapped to a technique covers it and its sub-techniques; one mapped to a sub-technique covers the parent too."""
    return rule_t == wanted or wanted.split(".")[0] == rule_t or rule_t.split(".")[0] == wanted


def version(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", str(v or "")))


@dataclass
class Rule:
    name: str
    kind: str = "Scheduled"
    enabled: bool = True
    severity: str = "Medium"
    tactics: list = field(default_factory=list)
    techniques: list = field(default_factory=list)
    tables: list = field(default_factory=list)
    frequency: str = ""
    source: str = "Custom"
    version: str = ""
    latest: str = ""
    modified: datetime | None = None

    @property
    def outdated(self) -> bool:
        return bool(self.version and self.latest and version(self.version) < version(self.latest))


@dataclass
class Source:
    name: str
    table: str
    owner: str = ""
    critical: bool = False
    delay: float | None = None           # hours; None -> settings.silent_hours


@dataclass
class Incident:
    id: str
    title: str
    rule: str
    severity: str = "Medium"
    status: str = "New"
    classification: str = ""
    owner: str = ""
    created: datetime | None = None
    first: datetime | None = None         # first change by an analyst (assigned, status changed)
    closed: datetime | None = None

    @property
    def is_open(self) -> bool:
        return _norm(self.status) != "closed"


@dataclass
class Health:
    time: datetime
    rule: str
    status: str
    reason: str = ""


@dataclass
class Priority:
    technique: str
    name: str = ""
    tactic: str = ""
    priority: str = "medium"
    why: str = ""


@dataclass
class Settings:
    organisation: str = "Your organisation"
    review: datetime = field(default_factory=datetime.now)
    days: int = 30                     # incidents and health looked at, back from the review
    silent_hours: float = 24           # a table with no record for this long is silent (unless sources.csv says otherwise)
    drop_pct: float = 50               # last week's daily volume this much below the weeks before it
    noisy_min: int = 10                # a rule needs at least this many closed incidents to be called noisy
    noisy_pct: float = 80              # false and benign positives, as a share of the classified incidents
    unused_gb: float = 1.0             # a table with this many GB a day that no enabled rule reads
    triage_hours: dict = field(default_factory=lambda: {"High": 4, "Medium": 24, "Low": 72})
    late_pct: float = 25               # share of incidents over the triage target that is too many, even when the median is fine
    open_days: int = 7                 # a High incident open for longer than this
    unclassified_pct: float = 20
    score_amber: float = 90.0
    score_red: float = 75.0
    previous_score: float | None = None
    owners: dict = field(default_factory=lambda: {"soc": "SOC", "engineering": "Detection engineering", "platform": "Log platform"})


@dataclass
class Data:
    rules: list[Rule]
    priorities: list[Priority]
    sources_expected: list[Source] = field(default_factory=list)
    last_record: dict = field(default_factory=dict)       # table -> datetime
    ingestion: dict = field(default_factory=dict)         # table -> {date: GB}
    incidents: list[Incident] = field(default_factory=list)
    health: list[Health] = field(default_factory=list)
    settings: Settings = field(default_factory=Settings)
    sources: dict = field(default_factory=dict)           # file -> rows loaded


def _read(path: Path) -> list[dict]:
    raw = path.read_bytes()
    text = raw.decode("utf-16") if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else raw.decode("utf-8-sig")
    head = text.splitlines()[0] if text else ""
    delim = ";" if head.count(";") > head.count(",") else ","
    return list(csv.DictReader(text.splitlines(), delimiter=delim))


def _rows(path: Path, aliases: dict) -> list[dict]:
    rows = _read(path)
    fields = list(rows[0].keys()) if rows else []
    lower = {_norm(f): f for f in fields if f}
    pick = {}
    for k, names in aliases.items():
        for n in names:
            if _norm(n) in lower:
                pick[k] = lower[_norm(n)]
                break
    return [{k: str(r.get(col) or "").strip() for k, col in pick.items()} for r in rows]


def _settings(path: Path) -> Settings:
    s = Settings()
    if not path.exists():
        return s
    for k, v in json.loads(path.read_text(encoding="utf-8")).items():
        if k == "review":
            s.review = parse_dt(v) or s.review
        elif k in ("owners", "triage_hours") and isinstance(v, dict):
            getattr(s, k).update(v)
        elif hasattr(s, k):
            setattr(s, k, v)
    return s


def severity(v) -> str:
    t = _norm(v)
    return {"high": "High", "medium": "Medium", "low": "Low", "informational": "Informational", "info": "Informational"}.get(t, "Medium")


def classification(v) -> str:
    t = _norm(v).replace(" ", "").replace("_", "")
    if t.startswith("truepositive"):
        return "TruePositive"
    if t.startswith("benignpositive"):
        return "BenignPositive"
    if t.startswith("falsepositive"):
        return "FalsePositive"
    if t.startswith("undetermined"):
        return "Undetermined"
    return ""


def load(folder: Path) -> Data:
    folder = Path(folder)
    for name, hint in (("rules.csv", "(Export-SentinelDetectionCoverage.ps1 writes it)"), ("priorities.csv", "(the organisation's priority techniques)")):
        if not (folder / name).exists():
            raise FileNotFoundError(f"{folder / name} not found: see docs/data-format.md {hint}")
    d = Data(rules=[], priorities=[], settings=_settings(folder / "settings.json"))
    for r in _rows(folder / "rules.csv", RULE_ALIASES):
        if r.get("name"):
            en = r.get("enabled", "yes")
            d.rules.append(Rule(r["name"], r.get("kind") or "Scheduled", yes(en) if en else True, severity(r.get("severity")), items(r.get("tactics")),
                                [t for t in (technique(x) for x in items(r.get("techniques"))) if t], items(r.get("tables")), r.get("frequency", ""),
                                r.get("source") or "Custom", r.get("version", ""), r.get("latest", ""), parse_dt(r.get("modified"))))
    for r in _rows(folder / "priorities.csv", PRIORITY_ALIASES):
        t = technique(r.get("technique"))
        if t:
            d.priorities.append(Priority(t, r.get("name", ""), r.get("tactic", ""), "high" if _norm(r.get("priority")) == "high" else "medium", r.get("why", "")))
    f = folder / "sources.csv"
    if f.exists():
        for r in _rows(f, SOURCE_ALIASES):
            if r.get("name") and r.get("table"):
                d.sources_expected.append(Source(r["name"], r["table"], r.get("owner", ""), yes(r.get("critical")),
                                                 number(r.get("delay"), 0) or None))
    f = folder / "tables.csv"
    if f.exists():
        for r in _rows(f, TABLE_ALIASES):
            t = parse_dt(r.get("last"))
            if r.get("table") and t:
                d.last_record[r["table"]] = t
    f = folder / "ingestion.csv"
    if f.exists():
        for r in _rows(f, INGEST_ALIASES):
            t = parse_dt(r.get("date"))
            if r.get("table") and t:
                day = d.ingestion.setdefault(r["table"], {})
                day[t.date()] = day.get(t.date(), 0.0) + number(r.get("gb"))
    f = folder / "incidents.csv"
    if f.exists():
        for r in _rows(f, INCIDENT_ALIASES):
            c = parse_dt(r.get("created"))
            if r.get("id") and c:
                d.incidents.append(Incident(r["id"], r.get("title", ""), r.get("rule", ""), severity(r.get("severity")), r.get("status") or "New",
                                            classification(r.get("classification")), r.get("owner", ""), c, parse_dt(r.get("first")), parse_dt(r.get("closed"))))
    f = folder / "health.csv"
    if f.exists():
        for r in _rows(f, HEALTH_ALIASES):
            t = parse_dt(r.get("time"))
            if r.get("rule") and t:
                d.health.append(Health(t, r["rule"], r.get("status", ""), r.get("reason", "")))
        d.health.sort(key=lambda h: h.time)
    d.sources = {"rules.csv": len(d.rules), "priorities.csv": len(d.priorities)}
    for name, n in (("sources.csv", len(d.sources_expected)), ("tables.csv", len(d.last_record)), ("ingestion.csv", sum(len(v) for v in d.ingestion.values())),
                    ("incidents.csv", len(d.incidents)), ("health.csv", len(d.health))):
        if (folder / name).exists():
            d.sources[name] = n
    return d
