"""The fictional demo: Fabrikam Logistics, reviewing its Microsoft Sentinel detection coverage on Wednesday 25 November
2026 with the incidents and rule health of the last 30 days. 22 priority techniques, 12 expected log sources, 38
analytics rules and a month of daily ingestion. The incidents follow the rules: a rule whose table went silent or whose
query fails stops raising incidents on the day it happened. Every name and figure is made up; the problems are placed on
purpose. The output is deterministic: the same files every run."""
from __future__ import annotations

import csv
import json
import random
from datetime import date, datetime, timedelta
from pathlib import Path

REVIEW = datetime(2026, 11, 25, 9, 0)
DAYS = 30
FW_SILENT = datetime(2026, 11, 20, 14, 12)       # the firewall collector stopped forwarding after a firmware upgrade
SYSLOG_DROP = date(2026, 11, 17)                 # a rsyslog change on half of the Linux servers
KERB_FAIL = datetime(2026, 11, 14, 3, 0)         # the Kerberoasting rule starts timing out

SETTINGS = {
    "organisation": "Fabrikam Logistics",
    "review": REVIEW.strftime("%Y-%m-%d %H:%M:%S"),
    "days": DAYS,
    "silent_hours": 24,
    "drop_pct": 50,
    "noisy_min": 10,
    "noisy_pct": 80,
    "unused_gb": 1.0,
    "triage_hours": {"High": 4, "Medium": 24, "Low": 72},
    "late_pct": 25,
    "open_days": 7,
    "unclassified_pct": 20,
    "score_amber": 90,
    "score_red": 75,
    "previous_score": 77.3,
    "owners": {"soc": "Marta Iglesias (SOC)", "engineering": "Daniel Ortega (Detection engineering)", "platform": "Sergio Romero (Log platform)"},
}

PRIORITIES = [  # Technique, Name, Tactic, Priority, Why
    ("T1078", "Valid Accounts", "Initial Access", "high", "Stolen passwords are how most intrusions here would start"),
    ("T1110.003", "Password Spraying", "Credential Access", "high", "Seen against the tenant every week"),
    ("T1566", "Phishing", "Initial Access", "high", "Carriers and customers send invoices by email all day"),
    ("T1059.001", "PowerShell", "Execution", "high", "First step of most hands-on-keyboard attacks"),
    ("T1003", "OS Credential Dumping", "Credential Access", "high", "Leads straight to domain admin"),
    ("T1021.001", "Remote Desktop Protocol", "Lateral Movement", "high", "RDP is open between the depot servers"),
    ("T1486", "Data Encrypted for Impact", "Impact", "high", "Ransomware would stop the warehouses"),
    ("T1490", "Inhibit System Recovery", "Impact", "high", "Deleting shadow copies comes just before encryption"),
    ("T1098", "Account Manipulation", "Persistence", "high", "MFA methods and roles added to stolen accounts"),
    ("T1114.003", "Email Forwarding Rule", "Collection", "high", "Invoice fraud starts with a forwarding rule"),
    ("T1567", "Exfiltration Over Web Service", "Exfiltration", "high", "Customer data uploaded to file-sharing sites"),
    ("T1558.003", "Kerberoasting", "Credential Access", "high", "Service accounts with old passwords"),
    ("T1136", "Create Account", "Persistence", "medium", ""),
    ("T1562", "Impair Defenses", "Defense Evasion", "medium", ""),
    ("T1070.001", "Clear Windows Event Logs", "Defense Evasion", "medium", ""),
    ("T1053.005", "Scheduled Task", "Persistence", "medium", ""),
    ("T1190", "Exploit Public-Facing Application", "Initial Access", "medium", "The carrier portal is on the internet"),
    ("T1133", "External Remote Services", "Initial Access", "medium", "Drivers' tablets and suppliers use the VPN"),
    ("T1071", "Application Layer Protocol", "Command and Control", "medium", ""),
    ("T1484", "Domain or Tenant Policy Modification", "Defense Evasion", "medium", ""),
    ("T1528", "Steal Application Access Token", "Credential Access", "medium", ""),
    ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", "medium", ""),
]

SOURCES = [  # Source, Table, Owner, Critical, MaxDelayHours
    ("Entra ID sign-ins", "SigninLogs", "Identity team", "yes", 6),
    ("Entra ID audit", "AuditLogs", "Identity team", "yes", 6),
    ("Domain controllers (security events)", "SecurityEvent", "Windows team", "yes", 6),
    ("Defender for Endpoint (processes)", "DeviceProcessEvents", "Workplace team", "yes", 6),
    ("Defender for Endpoint (logons)", "DeviceLogonEvents", "Workplace team", "no", 24),
    ("Defender for Identity", "IdentityDirectoryEvents", "Identity team", "no", 24),
    ("Microsoft 365 activity", "OfficeActivity", "Collaboration team", "yes", 6),
    ("Firewalls (CEF)", "CommonSecurityLog", "Network team", "yes", 6),
    ("Linux servers (syslog)", "Syslog", "Linux team", "no", 24),
    ("Azure activity", "AzureActivity", "Cloud team", "no", 24),
    ("AWS CloudTrail", "AWSCloudTrail", "Cloud team", "no", 24),
    ("Defender XDR alerts", "SecurityAlert", "Workplace team", "yes", 6),
]

GB = {"SigninLogs": 4.1, "AuditLogs": 0.9, "SecurityEvent": 21.5, "DeviceProcessEvents": 14.2, "DeviceLogonEvents": 3.4, "DeviceFileEvents": 9.8,
      "IdentityDirectoryEvents": 0.6, "OfficeActivity": 2.7, "CommonSecurityLog": 38.0, "Syslog": 6.2, "AzureActivity": 0.4, "SecurityAlert": 0.05,
      "AzureDiagnostics": 11.4, "ContainerLogV2": 3.2, "Heartbeat": 0.3, "ThreatIntelligenceIndicator": 0.2}

# Rule, Kind, Enabled, Severity, Tactics, Techniques, Tables, Frequency, Source, TemplateVersion, LatestVersion, Modified,
# then for the simulation: incidents a day, true positive share, benign share, false share
RULES = [
    ("Sign-in from an unfamiliar country", "Scheduled", "yes", "Medium", "InitialAccess", "T1078", "SigninLogs", "PT1H", "Custom", "", "", "2025-03-04", 4.6, .04, .62, .31),
    ("Impossible travel between two sign-ins", "Scheduled", "yes", "Medium", "InitialAccess", "T1078", "SigninLogs", "PT1H", "Content hub", "1.4.0", "1.4.0", "2025-09-18", .4, .25, .5, .2),
    ("Password spray against Entra ID", "Scheduled", "yes", "High", "CredentialAccess", "T1110.003", "SigninLogs", "PT1H", "Content hub", "2.0.1", "2.1.0", "2025-02-11", .5, .55, .25, .15),
    ("Sign-in to a break-glass account", "NRT", "yes", "High", "InitialAccess", "T1078", "SigninLogs", "", "Custom", "", "", "2026-01-20", .03, .5, .5, 0),
    ("Phishing link clicked (Defender XDR)", "Scheduled", "yes", "High", "InitialAccess", "T1566", "SecurityAlert", "PT15M", "Custom", "", "", "2025-06-02", .5, .5, .3, .15),
    ("Encoded PowerShell command line", "Scheduled", "yes", "Medium", "Execution", "T1059.001", "DeviceProcessEvents", "PT1H", "Content hub", "1.2.0", "1.3.2", "2025-05-12", .6, .2, .55, .2),
    ("LSASS memory read by an unsigned process", "NRT", "yes", "High", "CredentialAccess", "T1003", "DeviceProcessEvents", "", "Custom", "", "", "2025-10-07", .1, .6, .3, .1),
    ("RDP from the internet to a server", "Scheduled", "yes", "High", "LateralMovement;InitialAccess", "T1021.001;T1133", "CommonSecurityLog", "PT1H", "Custom", "", "", "2025-04-22", .25, .3, .4, .25),
    ("RDP between two workstations", "Scheduled", "yes", "Medium", "LateralMovement", "T1021.001", "DeviceLogonEvents", "PT1H", "Custom", "", "", "2025-04-22", .3, .3, .5, .15),
    ("Burst of renamed files with a new extension", "NRT", "yes", "High", "Impact", "T1486", "DeviceFileEvents", "", "Custom", "", "", "2025-08-30", .05, .5, .3, .2),
    ("Shadow copies deleted", "NRT", "no", "High", "Impact", "T1490", "DeviceProcessEvents", "", "Content hub", "1.1.0", "1.1.0", "2026-09-14", 0, 0, 0, 0),
    ("MFA method added to an admin account", "Scheduled", "yes", "High", "Persistence", "T1098", "AuditLogs", "PT30M", "Custom", "", "", "2026-02-03", .2, .3, .65, .05),
    ("Kerberoasting: RC4 service tickets for many accounts", "Scheduled", "yes", "High", "CredentialAccess", "T1558.003", "SecurityEvent", "PT1H", "Content hub", "1.0.2", "1.0.2", "2025-07-15", .1, .4, .4, .2),
    ("Large upload to a file-sharing site", "Scheduled", "yes", "High", "Exfiltration", "T1567", "CommonSecurityLog", "PT1H", "Custom", "", "", "2025-11-03", .3, .2, .55, .2),
    ("Mass download from SharePoint then upload out", "Scheduled", "yes", "High", "Exfiltration;Collection", "T1567", "OfficeActivity;CommonSecurityLog", "PT1H", "Custom", "", "", "2026-03-10", .1, .3, .5, .2),
    ("Account created and deleted within an hour", "Scheduled", "yes", "Medium", "Persistence", "T1136", "AuditLogs;SecurityEvent", "PT1H", "Content hub", "1.0.4", "1.0.4", "2025-02-11", .1, .2, .7, .1),
    ("Tamper protection turned off (Defender XDR)", "Scheduled", "yes", "High", "DefenseEvasion", "T1562", "SecurityAlert", "PT15M", "Custom", "", "", "2025-06-02", .05, .6, .3, .1),
    ("Security event log cleared", "NRT", "yes", "Medium", "DefenseEvasion", "T1070.001", "SecurityEvent", "", "Content hub", "1.0.1", "1.0.1", "2025-02-11", .08, .4, .5, .1),
    ("Scheduled task created by an unusual process", "Scheduled", "yes", "Medium", "", "", "DeviceProcessEvents", "PT1H", "Custom", "", "", "2026-05-19", .3, .2, .5, .3),
    ("Web attack blocked then allowed on the carrier portal", "Scheduled", "yes", "High", "InitialAccess", "T1190", "CommonSecurityLog", "PT1H", "Custom", "", "", "2026-01-12", .1, .3, .3, .4),
    ("VPN sign-in from a new country", "Scheduled", "yes", "Medium", "InitialAccess", "T1133", "CommonSecurityLog", "PT1H", "Custom", "", "", "2025-04-22", .6, .1, .7, .2),
    ("Beaconing to a rare domain", "Scheduled", "yes", "Medium", "CommandAndControl", "T1071", "CommonSecurityLog", "PT1H", "Custom", "", "", "2025-12-01", .3, .1, .4, .5),
    ("Connection to a threat intelligence address", "Scheduled", "yes", "Medium", "CommandAndControl", "T1071", "CommonSecurityLog;ThreatIntelligenceIndicator", "PT1H", "Content hub", "2.2.0", "2.2.0", "2025-09-18", .2, .2, .3, .5),
    ("Conditional Access policy changed", "Scheduled", "yes", "Medium", "DefenseEvasion", "T1484", "AuditLogs", "PT1H", "Custom", "", "", "2026-02-03", .15, .1, .85, .05),
    ("Group Policy object modified", "Scheduled", "yes", "Low", "DefenseEvasion", "T1484", "SecurityEvent", "PT1H", "Custom", "", "", "2025-03-04", .2, .05, .9, .05),
    ("OAuth app granted mail permissions", "Scheduled", "yes", "High", "CredentialAccess", "T1528", "AuditLogs", "PT1H", "Content hub", "1.0.3", "1.1.0", "2025-02-11", .07, .3, .6, .1),
    ("Large transfer from a Linux server", "Scheduled", "yes", "Medium", "Exfiltration", "T1048", "Syslog", "PT1H", "Custom", "", "", "2025-11-03", .1, .2, .5, .3),
    ("SSH brute force on a Linux server", "Scheduled", "yes", "Low", "CredentialAccess", "T1110", "Syslog", "PT1H", "Custom", "", "", "2025-11-03", .6, .05, .4, .5),
    ("Sudo to root by a new user", "Scheduled", "yes", "Medium", "PrivilegeEscalation", "T1548.003", "Syslog", "PT1H", "Custom", "", "", "2025-11-03", .1, .2, .7, .1),
    ("Multiple failed logons on a server", "Scheduled", "yes", "Low", "CredentialAccess", "T1110", "SecurityEvent", "PT1H", "Custom", "", "", "2025-03-04", 2.1, .03, .3, .6),
    ("AWS root account used", "NRT", "yes", "High", "InitialAccess;PrivilegeEscalation", "T1078.004", "AWSCloudTrail", "", "Content hub", "1.0.0", "1.0.0", "2026-04-08", 0, 0, 0, 0),
    ("AWS CloudTrail logging stopped", "Scheduled", "yes", "High", "DefenseEvasion", "T1562.008", "AWSCloudTrail", "PT1H", "Content hub", "1.0.0", "1.0.0", "2026-04-08", 0, 0, 0, 0),
    ("Admin sign-in outside working hours", "Scheduled", "yes", "Low", "", "", "SigninLogs", "PT1H", "Custom", "", "", "2026-06-23", .5, .05, .8, .1),
    ("Bulk external sharing from Teams", "Scheduled", "yes", "Medium", "", "", "OfficeActivity", "PT1H", "Custom", "", "", "2026-07-07", .2, .1, .7, .2),
    ("Printer driver installed by a user", "Scheduled", "yes", "Low", "", "", "DeviceProcessEvents", "P1D", "Custom", "", "", "2026-08-11", .2, .05, .7, .25),
    ("Advanced multistage attack detection", "Fusion", "yes", "High", "", "", "", "", "Microsoft", "", "", "2025-02-11", .03, .7, .2, .1),
    ("Defender XDR incidents", "MicrosoftSecurityIncidentCreation", "yes", "Medium", "", "", "SecurityAlert", "", "Microsoft", "", "", "2025-02-11", .5, .3, .5, .15),
    ("Test rule, do not use", "Scheduled", "no", "Low", "", "", "SigninLogs", "PT5M", "Custom", "", "", "2026-03-02", 0, 0, 0, 0),
]
ANALYSTS = ["ana.serrano", "hugo.medina", "paula.castro", "ivan.santos", "nerea.gil"]


def _down(tables: str, t: datetime) -> bool:
    """True when the rule could not have raised an incident at time t."""
    ts = tables.split(";") if tables else []
    if "AWSCloudTrail" in ts:
        return True
    if "CommonSecurityLog" in ts and t >= FW_SILENT:
        return True
    return False


def _incidents(rnd: random.Random) -> list:
    rows, n = [], 4101
    start = REVIEW - timedelta(days=DAYS + 3)
    for r in RULES:
        name, en, sev, tables, rate, tp, bp, fp = r[0], r[2], r[3], r[6], r[12], r[13], r[14], r[15]
        if en != "yes" or rate == 0:
            continue
        t = start
        while True:
            t += timedelta(hours=rnd.expovariate(rate / 24))
            if t >= REVIEW - timedelta(minutes=20):
                break
            if _down(tables, t) or (name.startswith("Kerberoasting") and t >= KERB_FAIL):
                continue
            weekend = t.weekday() >= 5
            night = t.hour < 7 or t.hour >= 20
            base = {"High": 2.5, "Medium": 7.0, "Low": 20.0}[sev]
            tri = rnd.lognormvariate(0, .6) * base * (2.6 if weekend else 1.0) * (1.8 if night else 1.0)
            first = t + timedelta(hours=tri)
            x = rnd.random()
            cls = "TruePositive" if x < tp else "BenignPositive" if x < tp + bp else "FalsePositive" if x < tp + bp + fp else "Undetermined"
            closed = first + timedelta(hours=rnd.uniform(.2, 6) * (3 if cls == "TruePositive" else 1))
            if first >= REVIEW:
                rows.append([n, name, sev, "New", "", "", t, None, None])
            elif closed >= REVIEW:
                rows.append([n, name, sev, "Active", "", rnd.choice(ANALYSTS), t, first, None])
            else:
                if rnd.random() < .27:
                    cls = ""
                rows.append([n, name, sev, "Closed", cls, rnd.choice(ANALYSTS), t, first, closed])
            n += 1
    rows.sort(key=lambda x: x[6])
    for i, x in enumerate(rows):
        x[0] = 4101 + i
    # two High incidents that nobody closed
    for x in rows:
        if x[1] == "Large upload to a file-sharing site" and x[6].date() == date(2026, 11, 9):
            x[3], x[4], x[5], x[8] = "Active", "", "hugo.medina", None
            break
    for x in rows:
        if x[1] == "Password spray against Entra ID" and date(2026, 11, 14) <= x[6].date() <= date(2026, 11, 16):
            x[3], x[4], x[5], x[7], x[8] = "New", "", "", None, None
            break
    f = lambda v: v.strftime("%Y-%m-%d %H:%M:%S") if v else ""
    return [[x[0], x[1], x[1], x[2], x[3], x[4], x[5], f(x[6]), f(x[7]), f(x[8])] for x in rows]


def _health(rnd: random.Random) -> list:
    rows = []
    for r in RULES:
        name, kind, en, freq = r[0], r[1], r[2], r[7]
        if en != "yes" or kind not in ("Scheduled", "NRT"):
            continue
        if name.startswith("Kerberoasting"):
            t = KERB_FAIL
            while t < REVIEW:
                rows.append([t, name, "Failure", "The query exceeded the time limit and was cancelled"])
                t += timedelta(hours=1)
            continue
        if name.startswith("Impossible travel"):
            for d in (datetime(2026, 11, 2, 4, 0), datetime(2026, 11, 9, 4, 0), datetime(2026, 11, 16, 4, 0)):
                rows.append([d, name, "Failure", "The query was throttled: too many queries at the same time"])
        last = REVIEW - timedelta(minutes=rnd.randint(3, 50) if kind == "Scheduled" and freq != "P1D" else rnd.randint(1, 5))
        if freq == "P1D":
            last = datetime(2026, 11, 25, 2, 0)
        rows.append([last, name, "Success", ""])
    rows.sort(key=lambda x: (x[0], x[1]))
    return [[x[0].strftime("%Y-%m-%d %H:%M:%S")] + x[1:] for x in rows]


def _ingestion(rnd: random.Random) -> tuple[list, list]:
    rows, last = [], []
    days = [REVIEW.date() - timedelta(days=i) for i in range(DAYS, 0, -1)]
    for t, gb in GB.items():
        for d in days:
            v = gb * rnd.uniform(.9, 1.1) * (.72 if d.weekday() >= 5 and t not in ("Heartbeat", "AzureDiagnostics") else 1)
            if t == "CommonSecurityLog":
                v = 0 if d > FW_SILENT.date() else v * (FW_SILENT.hour + FW_SILENT.minute / 60) / 24 if d == FW_SILENT.date() else v
            if t == "Syslog" and d >= SYSLOG_DROP:
                v *= .38
            if v > 0:
                rows.append([d.isoformat(), t, round(v, 3)])
        when = FW_SILENT if t == "CommonSecurityLog" else REVIEW - timedelta(minutes=rnd.randint(1, 40))
        last.append([t, when.strftime("%Y-%m-%d %H:%M:%S")])
    return rows, last


def _csv(path: Path, header: list[str], rows: list) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def write(folder: Path) -> Path:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    rnd = random.Random(63)
    ing, last = _ingestion(rnd)
    _csv(folder / "rules.csv", ["Rule", "Kind", "Enabled", "Severity", "Tactics", "Techniques", "Tables", "Frequency", "Source", "TemplateVersion",
                                "LatestVersion", "Modified"], [r[:12] for r in RULES])
    _csv(folder / "priorities.csv", ["Technique", "Name", "Tactic", "Priority", "Why"], PRIORITIES)
    _csv(folder / "sources.csv", ["Source", "Table", "Owner", "Critical", "MaxDelayHours"], SOURCES)
    _csv(folder / "tables.csv", ["Table", "LastRecord"], last)
    _csv(folder / "ingestion.csv", ["Date", "Table", "GB"], ing)
    _csv(folder / "incidents.csv", ["Incident", "Title", "Rule", "Severity", "Status", "Classification", "Owner", "Created", "FirstModified", "Closed"],
         _incidents(rnd))
    _csv(folder / "health.csv", ["Time", "Rule", "Status", "Reason"], _health(rnd))
    (folder / "settings.json").write_text(json.dumps(SETTINGS, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return folder
