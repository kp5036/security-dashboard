# 🔐 Security Dashboard

A full-stack threat intelligence web app that scans URLs and IP addresses for security threats using real-time data from multiple cybersecurity APIs.

🌐 **Live Demo:** https://security-dashboard-rqw4.onrender.com

## Features
- 🦠 **VirusTotal** — scans for malware across 70+ antivirus engines
- 🚨 **AbuseIPDB** — checks IP reputation and abuse history
- 🔎 **Shodan** — reveals open ports and organization info
- 🟢 Threat level badge (CLEAN / SUSPICIOUS / HIGH RISK)
- 📊 Interactive doughnut charts for visual threat analysis
- 🕓 Recent scan history on homepage

## Tech Stack
- **Backend:** Python, Flask
- **Frontend:** HTML, CSS, JavaScript, Chart.js
- **APIs:** VirusTotal, AbuseIPDB, Shodan
- **Deployment:** Render

## Run Locally
```bash
git clone https://github.com/kp5036/security-dashboard.git
cd security-dashboard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file with your API keys:
```
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
SHODAN_API_KEY=your_key
```

```bash
python app.py
```

## Author
Krish Patel — [GitHub](https://github.com/kp5036) | [LinkedIn](https://linkedin.com/in/krishpatel21) 