# 🔐 Security Dashboard

A full-stack threat intelligence dashboard that scans URLs and IP addresses using multiple cybersecurity APIs and visualizes risk indicators in a clean web interface.

🌐 **Live Demo:** https://security-dashboard-rqw4.onrender.com

---

## Overview

Security Dashboard is a Python/Flask web application built to practice cybersecurity automation, API integration, and threat intelligence workflows. The app allows a user to submit a URL or IP address and receive security context from multiple external sources, including malware detection, IP reputation, abuse history, and exposed service information.

This project demonstrates how security analysts can combine multiple intelligence sources into a single dashboard for faster triage and decision-making.

---

## Features

- URL and IP threat scanning
- VirusTotal integration for malware and URL reputation checks
- AbuseIPDB integration for IP abuse confidence scoring
- Shodan integration for open port and organization intelligence
- Dynamic threat-level badge: CLEAN, SUSPICIOUS, or HIGH RISK
- Interactive Chart.js visualizations for scan results
- Recent scan history displayed on the homepage
- API key handling through environment variables
- Public deployment using Render

---

## Security Concepts Demonstrated

- Threat intelligence aggregation
- URL and IP reputation analysis
- API-based security automation
- Risk scoring and alert-style classification
- Open-source intelligence fundamentals
- Secure API key handling with environment variables
- Basic security dashboard design for analyst workflows

---

## Tech Stack

**Backend:** Python, Flask  
**Frontend:** HTML, CSS, JavaScript, Chart.js  
**Security APIs:** VirusTotal, AbuseIPDB, Shodan  
**Deployment:** Render, gunicorn  
**Development Tools:** Git, GitHub, CLI

---

## Architecture

```text
User Input
   ↓
Flask Backend
   ↓
VirusTotal API / AbuseIPDB API / Shodan API
   ↓
Threat Scoring Logic
   ↓
Chart.js Dashboard + Threat Badge + Scan History%
