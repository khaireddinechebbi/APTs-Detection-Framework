# 🛡️ Automated Threat Intelligence & APT Detection

## 📖 Overview

This project focuses on detecting **APT29** and **Lazarus Group** techniques using the **MITRE ATT\&CK framework**.
We developed and tested **Sigma detection rules** mapped to real-world adversary TTPs, deployed them in **Elastic (Kibana + Sysmon)**, and validated against **Atomic Red Team simulations**.

The outcome is a **tested detection ruleset**, an **ATT\&CK Navigator coverage layer**, and a **detection report** documenting results, false positives, and enrichment plans.

---

## 🎯 Objectives

* Map detection coverage to **APT29 & Lazarus** behaviors.
* Develop **Sigma rules** for key MITRE ATT\&CK techniques.
* Validate rules in a live SIEM environment.
* Identify **false positives** and propose tuning strategies.
* Provide a foundation for future **threat intelligence enrichment** (VirusTotal, OTX, MISP/OpenCTI).

---

## 🛠️ Tools & Frameworks

* **Sigma** – rule format for SIEMs
* **Elastic + Kibana** – log collection & visualization
* **Sysmon + Winlogbeat** – Windows telemetry
* **Atomic Red Team** – adversary simulation
* **ATT\&CK Navigator** – coverage mapping
* (Planned) **MISP / OpenCTI, VirusTotal API, AlienVault OTX** – enrichment

---

## 📂 Repository Structure

```
├── sigma-rules/          # Sigma YAML rules (mapped to ATT&CK)
├── navigator-layer/      # ATT&CK Navigator JSON (APT29 + Lazarus coverage)
├── report/               # Detection report (PDF/Markdown)
├── test-logs/            # Simulation logs & Kibana screenshots
└── README.md             # This file
```

---

## 📊 Detection Coverage

* **Total Techniques Covered:** 18
* **Severity:** 1 Critical, 15 High, 2 Medium
* **Groups:** APT29, Lazarus
* See `navigator-layer/apts_project_(apt29_+_lazarus_group).json` for full ATT\&CK matrix mapping.

---

## ✅ Results

* Rules tested against **11 MITRE techniques** with **true positives confirmed**.
* Extended with **7 more rules** (Credential Dumping, Discovery, Persistence, C2, Exfiltration).
* False positives logged and mitigation strategies proposed.
* Enrichment plan drafted for correlation with OSINT threat intel sources.

---

## 🚀 How to Use

1. Deploy **Sysmon** + **Winlogbeat** to forward Windows events to Elastic.
2. Import Sigma rules into your SIEM (via [sigmac](https://github.com/SigmaHQ/sigma) or native Sigma support).
3. Simulate APT behaviors with [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team).
4. Monitor alerts in Kibana.
5. Use `report/` docs to evaluate FP/TP results and adjust tuning.

---

## 📈 Future Work

* Expand detection coverage for persistence & exfiltration.
* Integrate with **MISP/OpenCTI** for IOC correlation.
* Automate IOC enrichment via **VirusTotal** & **OTX** APIs.
* Continuous false positive tuning and SOC-ready dashboards.

---

## 👤 Authors

* Khaireddine Chebbi