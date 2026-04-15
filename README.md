# 🛡️ Log-Sentinel — Cybersecurity + Anomaly Detection Prototype

> **Team TechDrift** | IEEE CIS Hackathon | Track: CyberSec (Sponsored)  
> Members: Swarai Wath · Tanavi Pandao · Gauravi Chakote · Rushi Gujarathi


This project is an end-to-end security analytics pipeline designed to detect, understand, and explain suspicious activities from system and application logs.
Instead of just flagging anomalies, the system focuses on connecting events, understanding context, and explaining threats in plain language, making it useful for both engineers and security analysts.

What This Project Does
Modern systems generate massive volumes of logs, but raw logs alone don’t tell a story.

This system:
•	Processes raw logs into structured data 
•	Detects unusual patterns using both rules and machine learning 
•	Correlates events across time to identify attack behavior 
•	Explains why something is suspicious using AI 
•	Assigns risk scores to help prioritize responses

 What This Project Does
Modern systems generate massive volumes of logs, but raw logs alone don’t tell a story.
This system:
•	Processes raw logs into structured data 
•	Detects unusual patterns using both rules and machine learning 
•	Correlates events across time to identify attack behavior 
•	Explains why something is suspicious using AI 
•	Assigns risk scores to help prioritize responses 
________________________________________
🏗️ How the System Works
The pipeline is built as a sequence of focused layers, each responsible for a specific task:
1. Log Ingestion
The system collects logs from multiple sources such as:
•	System logs 
•	Application logs 
•	Authentication logs 
These logs are batched and passed forward for processing.
________________________________________
2. Preprocessing
Raw logs are noisy and inconsistent. This stage:
•	Parses log entries 
•	Extracts meaningful features (IP, timestamp, user, action, etc.) 
•	Converts everything into a structured format 
________________________________________
3. Detection Engine
This is where anomalies are identified using a hybrid approach:
•	Rule-based detection for known patterns (e.g., repeated login failures) 
•	Isolation Forest for unknown or unusual behavior 
The output is a set of flagged events.
________________________________________
4. Intelligence Layer
Instead of treating events independently, this layer connects them:
•	Correlates related events 
•	Identifies sequences (e.g., failed → success login) 
•	Analyzes context like time, frequency, and user behavior 
This is where actual attack patterns begin to emerge.
________________________________________
5. Explainability Layer
This is the core differentiator of the project.
Using an LLM (via LangGraph), the system:
•	Converts technical detections into human-readable explanations 
•	Explains why something is suspicious 
•	Summarizes attack scenarios clearly 
________________________________________
6. Risk Scoring
Each detected threat is evaluated and assigned a score based on:
•	Severity 
•	Frequency 
•	Context 
This helps prioritize what needs immediate attention.
________________________________________
7. Output & Visualization
Finally, results are presented as:
•	Threat reports 
•	Alerts/notifications 
•	Dashboard visualizations 

Key Capabilities
1. Attack Flow Reconstruction
The system doesn’t just flag events — it connects them.
Example:
Multiple failed logins followed by a successful attempt can indicate a brute-force attack.
________________________________________
 2.Context-Aware Detection
Decisions are not made in isolation.
Example:
A login at an unusual hour from a new IP address is treated differently than a normal login.
________________________________________
3. Noise Reduction
Large volumes of harmless logs are filtered out so only meaningful signals remain.
________________________________________
4. Risk-Based Prioritization
Not all alerts are equal — the system ranks them so critical threats stand out.
________________________________________
5. Explainable Insights
Every flagged threat comes with a clear explanation, not just a label.
________________________________________


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

## 🌐 Future Scope

1. **Real-time streaming** — Kafka/Fluentd integration for live log feeds
2. **LLM explanations** — LangGraph + Claude/GPT for natural language threat narratives
3. **SIEM integration** — Connect to Splunk, Elastic, or cloud security platforms
4. **Auto-response** — Automated IP blocking / account lockout triggers
5. **Behavioral baselines** — Learn per-user normal patterns to improve detection
---

