# 🛡️ Log-Sentinel — Cybersecurity + Anomaly Detection Prototype

> **Team TechDrift** | IEEE CIS Hackathon | Track: CyberSec (Sponsored)  
> Members: Swarai Wath · Tanavi Pandao · Gauravi Chakote · Rushi Gujarathi

---

## 📌 What is Log-Sentinel?

Log-Sentinel is an AI-powered log analysis system that:
- **Parses** raw `.log` files into structured events
- **Detects anomalies** using Isolation Forest (ML) + a Rule Engine
- **Reconstructs attack chains** by correlating multi-step events
- **Ranks threats** by severity (risk score 0–100)
- **Generates a security briefing** with AI recommendations
- **Visualizes everything** in an interactive dark-mode dashboard

---

## 📁 Project Structure

```
log-sentinel/
├── src/
│   └── detector.py          ← Python ML engine (Isolation Forest + Rule Engine)
├── public/
│   └── dashboard.html       ← Interactive browser dashboard (no server needed!)
├── sample-logs/
│   └── system.log           ← Sample log file with embedded attack patterns
├── output/                  ← Auto-created on first run
│   ├── analysis.json        ← Structured JSON results
│   └── security_briefing.txt← Human-readable security report
└── README.md                ← This file
```

---

## 🚀 Quick Start

### Option A — Browser Dashboard (Easiest, no install)
1. Open `public/dashboard.html` in any modern browser (Chrome/Firefox/Edge)
2. Click **"Use Sample Log (Demo)"** to see instant results
3. Or drag-and-drop your own `.log` file

### Option B — Python CLI Engine

**Requirements:**
```bash
pip install scikit-learn pandas numpy
```

**Run:**
```bash
cd log-sentinel
python src/detector.py sample-logs/system.log
```

**With custom output paths:**
```bash
python src/detector.py your-file.log --json output/results.json --report output/report.txt
```

---

## 📊 Log Format Supported

```
YYYY-MM-DD HH:MM:SS LEVEL user=NAME src_ip=IP action=ACTION [path=PATH] status=STATUS
```

**Example:**
```
2024-03-15 09:16:13 CRITICAL user=admin src_ip=203.0.113.45 action=LOGIN status=SUCCESS
2024-03-15 09:16:30 CRITICAL user=admin src_ip=203.0.113.45 action=FILE_ACCESS path=/etc/passwd status=SUCCESS
```

---

## 🧠 How It Works

### 1. Log Parsing
Regex-based parser extracts: timestamp, severity level, user, IP, action, file path, status.

### 2. Feature Engineering
| Feature | Description |
|---------|-------------|
| `is_external_ip` | IP outside RFC1918 ranges |
| `is_off_hours` | Activity before 6AM or after 10PM |
| `is_failed` | Failed action flag |
| `is_sensitive` | Access to passwd/shadow/financial files |
| `user_fail_count` | Total failures per user |
| `user_ip_variety` | Number of distinct IPs per user |

### 3. Isolation Forest (ML)
- Unsupervised anomaly detection
- 200 estimators, 15% contamination rate
- Converts anomaly scores to 0–100 risk scale

### 4. Rule Engine
| Rule | Trigger | Risk Boost |
|------|---------|------------|
| BRUTE_FORCE_ATTEMPT | 5+ fails from same IP | +40 |
| BRUTE_FORCE_SUCCESS | Brute IP → successful login | +85 |
| OFF_HOURS_EXTERNAL_LOGIN | External IP + odd hours login | +75 |
| SENSITIVE_FILE_ACCESS | /etc/passwd, /etc/shadow, /financial/* | +60 |
| DATA_EXFILTRATION | action=DATA_EXFILTRATION | +95 |
| PRIVILEGE_ESCALATION | action=PRIVILEGE_ESCALATION | +90 |

### 5. Attack Chain Reconstruction
Groups anomalous events by source IP, detects:
- **Brute-Force** → multiple fails + success
- **Data Exfiltration** → login → sensitive access → export
- **Privilege Escalation** → file access → priv escalation
- **Off-Hours Access** → external IP at 3AM

### 6. Threat Ranking
Chains sorted by maximum risk score. Top 5 displayed prominently.

---

## 🔍 Sample Output

```
============================================================
   LOG-SENTINEL — SECURITY BRIEFING
   Analysis Date: 2024-03-15 13:06:47
============================================================

📊 SUMMARY
   Total log events : 37
   Anomalies flagged: 21 (56.8%)
   Attack chains    : 4

────────────────────────────────────────────────────────────
🔍 TOP 5 THREATS (ranked by risk score)
────────────────────────────────────────────────────────────

#1  🔴 [CRITICAL]  Data Exfiltration
    Source IP   : 185.220.101.5
    Risk Score  : 100.0/100
    Events      : 3
    Description : Suspicious data export detected from 185.220.101.5 after login activity.
    Attack Timeline:
      2024-03-15 03:14:22  eve         LOGIN                     SUCCESS  ← OFF_HOURS_EXTERNAL_LOGIN
      2024-03-15 03:14:45  eve         FILE_ACCESS               SUCCESS  ← SENSITIVE_FILE_ACCESS
      2024-03-15 03:15:10  eve         DATA_EXFILTRATION         SUCCESS  ← DATA_EXFILTRATION

#2  🔴 [CRITICAL]  Brute-Force Attack
    Source IP   : 203.0.113.45
    Risk Score  : 90.6/100
    Events      : 9
    Description : Attacker at 203.0.113.45 performed repeated failed logins then successfully authenticated.
```

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Data Processing | Python, Pandas | Parse & structure raw logs |
| Detection Engine | Isolation Forest (sklearn) | Unsupervised anomaly detection |
| Rule Engine | Python (custom) | Domain-specific threat rules |
| Intelligence Layer | Feature Engineering + Pattern Analysis | Multi-event attack chain correlation |
| Output | JSON + Text Report | Structured + human-readable results |
| Frontend | HTML5 + Vanilla JS | Interactive browser dashboard |

---

## 🌐 Future Scope

1. **Real-time streaming** — Kafka/Fluentd integration for live log feeds
2. **LLM explanations** — LangGraph + Claude/GPT for natural language threat narratives
3. **SIEM integration** — Connect to Splunk, Elastic, or cloud security platforms
4. **Auto-response** — Automated IP blocking / account lockout triggers
5. **Behavioral baselines** — Learn per-user normal patterns to improve detection

---

## 📧 Team Contact

| Name | Role |
|------|------|
| Swarai Wath | ML & Detection Engine |
| Tanavi Pandao | Frontend & Dashboard |
| Gauravi Chakote | System Architecture |
| Rushi Gujarathi | Rule Engine & Integration |

---

*Log-Sentinel — "From raw logs to actionable intelligence in seconds."*
