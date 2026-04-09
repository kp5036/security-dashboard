from flask import Flask, render_template, request
from dotenv import load_dotenv
import requests
import os

load_dotenv()
scan_history = []
app = Flask(__name__)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

def check_virustotal(target):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    # Check if it's an IP or URL
    import re
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    
    if re.match(ip_pattern, target):
        # Use IP endpoint
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{target}",
            headers=headers
        )
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
    else:
        # Use URL endpoint
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": target}
        )
        result = response.json()
        url_id = result["data"]["id"]
        analysis = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{url_id}",
            headers=headers
        )
        data = analysis.json()
        stats = data["data"]["attributes"]["stats"]
    
    return stats

def check_abuseipdb(target):
    import re
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    
    # AbuseIPDB only works with IPs
    if not re.match(ip_pattern, target):
        return {"error": "AbuseIPDB only supports IP addresses, not URLs"}
    
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    response = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers=headers,
        params={"ipAddress": target, "maxAgeInDays": 90}
    )
    data = response.json()
    return {
        "abuse_score": data["data"]["abuseConfidenceScore"],
        "country": data["data"]["countryCode"],
        "total_reports": data["data"]["totalReports"]
    }
def check_shodan(ip):
    response = requests.get(
        f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    )
    data = response.json()
    return {
        "ports": data.get("ports", []),
        "org": data.get("org", "Unknown"),
        "country": data.get("country_name", "Unknown")
    }

@app.route("/")
def home():
    return render_template("index.html", history=scan_history)

@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target")
    results = {}
    
    try:
        results["virustotal"] = check_virustotal(target)
    except Exception as e:
        results["virustotal"] = {"error": str(e)}

    try:
        results["abuseipdb"] = check_abuseipdb(target)
    except Exception as e:
        results["abuseipdb"] = {"error": str(e)}

    try:
        results["shodan"] = check_shodan(target)
    except Exception as e:
        results["shodan"] = {"error": str(e)}

    scan_history.append({
        "target": target,
        "threat": "HIGH RISK" if results.get("virustotal", {}).get("malicious", 0) > 0 else "CLEAN"
    })
    if len(scan_history) > 5:
        scan_history.pop(0)

    #return render_template("results.html", target=target, results=results)
    return render_template("results.html", target=target, results=results)

if __name__ == "__main__":
    app.run(debug=True)