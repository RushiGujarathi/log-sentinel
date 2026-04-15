#!/usr/bin/env python3
"""
Log-Sentinel: Anomaly Detection Engine
Team TechDrift - IEEE CIS Hackathon
"""

import re
import json
import sys
import argparse
from datetime import datetime
from collections import defaultdict

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

# ──────────────────────────────────────────────
#  PARSER
# ──────────────────────────────────────────────

LOG_PATTERN = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<level>\w+)\s+user=(?P<user>\S+)\s+src_ip=(?P<src_ip>\S+)\s+"
    r"action=(?P<action>\S+)(?:\s+path=(?P<path>\S+))?\s+status=(?P<status>\S+)"
)

def parse_logs(filepath: str) -> pd.DataFrame:
    rows = []
    with open(filepath) as f:
        for line in f:
            m = LOG_PATTERN.match(line.strip())
            if m:
                d = m.groupdict()
                dt_str = f"{d['date']} {d['time']}"
                dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
                rows.append({
                    "timestamp": dt,
                    "date": d["date"],
                    "time": d["time"],
                    "hour": dt.hour,
                    "level": d["level"],
                    "user": d["user"],
                    "src_ip": d["src_ip"],
                    "action": d["action"],
                    "path": d.get("path") or "",
                    "status": d["status"],
                    "raw": line.strip(),
                })
    df = pd.DataFrame(rows)
    df.sort_values("timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df

# ──────────────────────────────────────────────
#  FEATURE ENGINEERING
# ──────────────────────────────────────────────

INTERNAL_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\."),
]

def is_external_ip(ip: str) -> int:
    return 0 if any(p.match(ip) for p in INTERNAL_RANGES) else 1

def is_sensitive_path(path: str) -> int:
    keywords = ["passwd", "shadow", "secret", "private", "financial",
                 "sensitive", "db_dump", "transactions", "accounts"]
    return 1 if any(k in path.lower() for k in keywords) else 0

def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    # Base features
    df["is_external_ip"] = df["src_ip"].apply(is_external_ip)
    df["is_off_hours"]   = df["hour"].apply(lambda h: 1 if (h < 6 or h >= 22) else 0)
    df["is_failed"]      = (df["status"] == "FAILED").astype(int)
    df["is_sensitive"]   = df["path"].apply(is_sensitive_path)
    df["is_critical"]    = (df["level"] == "CRITICAL").astype(int)

    # Per-user stats
    user_fail = df.groupby("user")["is_failed"].transform("sum")
    df["user_fail_count"] = user_fail

    # IP variety per user
    user_ip_count = df.groupby("user")["src_ip"].transform("nunique")
    df["user_ip_variety"] = user_ip_count

    # Encode categoricals
    le_action = LabelEncoder()
    le_status = LabelEncoder()
    le_level  = LabelEncoder()
    df["action_enc"] = le_action.fit_transform(df["action"])
    df["status_enc"] = le_status.fit_transform(df["status"])
    df["level_enc"]  = le_level.fit_transform(df["level"])

    return df

# ──────────────────────────────────────────────
#  ISOLATION FOREST
# ──────────────────────────────────────────────

FEATURE_COLS = [
    "hour", "is_external_ip", "is_off_hours",
    "is_failed", "is_sensitive", "is_critical",
    "user_fail_count", "user_ip_variety",
    "action_enc", "status_enc", "level_enc",
]

def run_isolation_forest(df: pd.DataFrame, contamination: float = 0.15):
    X = df[FEATURE_COLS].fillna(0)
    clf = IsolationForest(n_estimators=200, contamination=contamination, random_state=42)
    clf.fit(X)
    scores = clf.decision_function(X)   # lower = more anomalous
    preds  = clf.predict(X)             # -1 = anomaly
    df = df.copy()
    df["anomaly_score_raw"] = scores
    df["is_anomaly"]        = (preds == -1).astype(int)
    # Normalise to 0-100 risk score (higher = riskier)
    mn, mx = scores.min(), scores.max()
    df["risk_score"] = ((scores - mx) / (mn - mx + 1e-9) * 100).clip(0, 100).round(1)
    return df

# ──────────────────────────────────────────────
#  RULE ENGINE
# ──────────────────────────────────────────────

def rule_engine(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["rule_flags"] = ""

    # Brute-force: 5+ failed logins same IP in window
    fail_df = df[df["is_failed"] == 1].copy()
    brute_ips = fail_df.groupby("src_ip").filter(lambda g: len(g) >= 5)["src_ip"].unique()
    df.loc[df["src_ip"].isin(brute_ips) & (df["is_failed"] == 0) & (df["action"] == "LOGIN"), "rule_flags"] += "BRUTE_FORCE_SUCCESS;"
    df.loc[df["src_ip"].isin(brute_ips) & (df["is_failed"] == 1), "rule_flags"] += "BRUTE_FORCE_ATTEMPT;"

    # Off-hours login from external IP
    mask = (df["is_off_hours"] == 1) & (df["is_external_ip"] == 1) & (df["action"] == "LOGIN") & (df["status"] == "SUCCESS")
    df.loc[mask, "rule_flags"] += "OFF_HOURS_EXTERNAL_LOGIN;"

    # Sensitive file access
    df.loc[df["is_sensitive"] == 1, "rule_flags"] += "SENSITIVE_FILE_ACCESS;"

    # Data exfiltration
    df.loc[df["action"] == "DATA_EXFILTRATION", "rule_flags"] += "DATA_EXFILTRATION;"

    # Privilege escalation
    df.loc[df["action"] == "PRIVILEGE_ESCALATION", "rule_flags"] += "PRIVILEGE_ESCALATION;"

    # Boost risk score for rule hits
    df.loc[df["rule_flags"] != "", "risk_score"] = (df.loc[df["rule_flags"] != "", "risk_score"] * 1.3).clip(0, 100).round(1)
    df.loc[df["rule_flags"] != "", "is_anomaly"] = 1

    return df

# ──────────────────────────────────────────────
#  ATTACK SEQUENCE RECONSTRUCTION
# ──────────────────────────────────────────────

def reconstruct_attack_chains(df: pd.DataFrame) -> list[dict]:
    chains = []
    anomalies = df[df["is_anomaly"] == 1].copy()

    # Group by source IP
    for ip, grp in anomalies.groupby("src_ip"):
        if len(grp) < 2:
            continue
        grp = grp.sort_values("timestamp")
        events = grp[["timestamp", "user", "action", "status", "rule_flags", "risk_score"]].to_dict("records")
        flags = set(";".join(grp["rule_flags"]).split(";")) - {""}

        # Classify chain
        if "BRUTE_FORCE_SUCCESS" in flags:
            chain_type = "Brute-Force Attack"
            severity = "CRITICAL"
            desc = (f"Attacker at {ip} performed repeated failed logins followed by a "
                    "successful authentication — classic brute-force pattern.")
        elif "DATA_EXFILTRATION" in flags:
            chain_type = "Data Exfiltration"
            severity = "CRITICAL"
            desc = f"Suspicious data export detected from {ip} after login activity."
        elif "PRIVILEGE_ESCALATION" in flags:
            chain_type = "Privilege Escalation"
            severity = "HIGH"
            desc = f"User at {ip} escalated privileges after accessing sensitive files."
        elif "OFF_HOURS_EXTERNAL_LOGIN" in flags:
            chain_type = "Suspicious Off-Hours Access"
            severity = "HIGH"
            desc = f"Login from external IP {ip} during off-hours (03:00–06:00)."
        elif "SENSITIVE_FILE_ACCESS" in flags:
            chain_type = "Sensitive File Access"
            severity = "MEDIUM"
            desc = f"Access to sensitive system files from {ip}."
        else:
            chain_type = "Anomalous Behaviour"
            severity = "MEDIUM"
            desc = f"Multiple anomalous events detected from {ip}."

        max_risk = grp["risk_score"].max()
        chains.append({
            "src_ip": ip,
            "chain_type": chain_type,
            "severity": severity,
            "description": desc,
            "risk_score": round(max_risk, 1),
            "event_count": len(grp),
            "events": [
                {
                    "time": str(e["timestamp"]),
                    "user": e["user"],
                    "action": e["action"],
                    "status": e["status"],
                    "flags": [f for f in e["rule_flags"].split(";") if f],
                }
                for e in events
            ],
        })

    # Sort by risk score descending
    chains.sort(key=lambda c: c["risk_score"], reverse=True)
    return chains

# ──────────────────────────────────────────────
#  SECURITY BRIEFING GENERATOR
# ──────────────────────────────────────────────

SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

def generate_briefing(chains: list[dict], df: pd.DataFrame) -> str:
    total = len(df)
    anomalies = int(df["is_anomaly"].sum())
    pct = round(anomalies / total * 100, 1)
    top = chains[:5]

    lines = [
        "=" * 60,
        "   LOG-SENTINEL — SECURITY BRIEFING",
        f"   Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 60,
        "",
        f"📊 SUMMARY",
        f"   Total log events : {total}",
        f"   Anomalies flagged: {anomalies} ({pct}%)",
        f"   Attack chains    : {len(chains)}",
        "",
        "─" * 60,
        "🔍 TOP 5 THREATS (ranked by risk score)",
        "─" * 60,
    ]

    for i, c in enumerate(top, 1):
        em = SEVERITY_EMOJI.get(c["severity"], "⚪")
        lines += [
            "",
            f"#{i}  {em} [{c['severity']}]  {c['chain_type']}",
            f"    Source IP   : {c['src_ip']}",
            f"    Risk Score  : {c['risk_score']}/100",
            f"    Events      : {c['event_count']}",
            f"    Description : {c['description']}",
            "    Attack Timeline:",
        ]
        for ev in c["events"]:
            flag_str = f"  ← {', '.join(ev['flags'])}" if ev["flags"] else ""
            lines.append(f"      {ev['time'][:19]}  {ev['user']:10}  {ev['action']:25} {ev['status']}{flag_str}")

    lines += [
        "",
        "─" * 60,
        "💡 AI RECOMMENDATIONS",
        "─" * 60,
    ]

    seen_types = set()
    for c in top:
        if c["chain_type"] not in seen_types:
            seen_types.add(c["chain_type"])
            if c["chain_type"] == "Brute-Force Attack":
                lines.append("  • Implement account lockout after 5 failed attempts.")
                lines.append("  • Enable MFA for all admin accounts.")
            elif c["chain_type"] == "Data Exfiltration":
                lines.append("  • Review DLP policies and egress filtering.")
                lines.append("  • Audit user permissions for sensitive directories.")
            elif c["chain_type"] == "Privilege Escalation":
                lines.append("  • Apply principle of least privilege.")
                lines.append("  • Monitor sudo/privilege logs in real time.")
            elif "Off-Hours" in c["chain_type"]:
                lines.append("  • Investigate off-hours login from foreign IPs.")
                lines.append("  • Set up geo-blocking rules for unusual regions.")
            elif "Sensitive" in c["chain_type"]:
                lines.append("  • Restrict access to /etc/passwd and /etc/shadow.")
                lines.append("  • Enable file integrity monitoring (FIM).")

    lines += ["", "=" * 60, "   End of Log-Sentinel Report", "=" * 60]
    return "\n".join(lines)

# ──────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────

def analyse(filepath: str, out_json: str = None, out_report: str = None):
    print(f"[Log-Sentinel] Parsing {filepath}...")
    df = parse_logs(filepath)
    print(f"  → {len(df)} log entries parsed")

    print("[Log-Sentinel] Engineering features...")
    df = engineer_features(df)

    print("[Log-Sentinel] Running Isolation Forest...")
    df = run_isolation_forest(df)

    print("[Log-Sentinel] Applying rule engine...")
    df = rule_engine(df)

    print("[Log-Sentinel] Reconstructing attack chains...")
    chains = reconstruct_attack_chains(df)

    print("[Log-Sentinel] Generating security briefing...")
    briefing = generate_briefing(chains, df)
    print(briefing)

    # Outputs
    result = {
        "summary": {
            "total_events": len(df),
            "anomalies": int(df["is_anomaly"].sum()),
            "attack_chains": len(chains),
            "analysis_timestamp": datetime.now().isoformat(),
        },
        "top_threats": chains[:5],
        "all_anomalies": df[df["is_anomaly"] == 1][
            ["timestamp", "user", "src_ip", "action", "status", "risk_score", "rule_flags"]
        ].assign(timestamp=lambda x: x["timestamp"].astype(str)).to_dict("records"),
    }

    if out_json:
        with open(out_json, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"\n[Log-Sentinel] JSON saved → {out_json}")

    if out_report:
        with open(out_report, "w") as f:
            f.write(briefing)
        print(f"[Log-Sentinel] Report saved → {out_report}")

    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Log-Sentinel: Anomaly Detection Engine")
    parser.add_argument("logfile", nargs="?", default="sample-logs/system.log")
    parser.add_argument("--json",   default="output/analysis.json",  help="JSON output path")
    parser.add_argument("--report", default="output/security_briefing.txt", help="Text report path")
    args = parser.parse_args()

    import os
    os.makedirs("output", exist_ok=True)
    analyse(args.logfile, args.json, args.report)
