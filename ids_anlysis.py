from flask import Flask, render_template, jsonify
import logging
import random
import threading
import time
import re
from datetime import datetime
from collections import Counter
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from bloom_filter import BloomFilter

app = Flask(__name__)

# IDS Configuration and parameters
rules = {
    "brute_force_threshold": 5,
    "port_scan_threshold": 10,
    "suspicious_ip_list": ["192.168.1.10", "10.0.0.5"],
    "malicious_ip_file": "malicious_ips.txt",
    "log_file": "logs.txt",
    "phishing_keywords": ["login", "verify", "account", "update", "security", "bank", "free"],
    "ddos_threshold": 50,
}

# Initialize logging to output to file
logging.basicConfig(filename=rules['log_file'], level=logging.INFO, format='%(asctime)s - %(message)s')

# Bloom filter for malicious IP detection
malicious_ip_filter = BloomFilter(max_elements=100000, error_rate=0.1)

# Load malicious IPs into the Bloom filter
try:
    with open(rules["malicious_ip_file"], "r") as file:
        for line in file:
            ip = line.strip()
            if ip and re.match(r"\d+\.\d+\.\d+\.\d+", ip):  # Ensure line is not empty and is a valid IP
                malicious_ip_filter.add(ip)
            else:
                logging.warning(f"Skipping invalid IP: {line.strip()}")
except FileNotFoundError:
    logging.error(f"Malicious IP file {rules['malicious_ip_file']} not found!")

# Data structures for simulation
failed_login_attempts = 0
ports_accessed = 0
request_data = []
alert_list = []  # Store alerts to serve to frontend

# K-means Model Initialization
scaler = StandardScaler()
kmeans = KMeans(n_clusters=2, random_state=42)  # 2 clusters for normal and anomaly

# Function to simulate brute force attacks
def simulate_brute_force():
    global failed_login_attempts
    failed_login_attempts += 1
    if failed_login_attempts >= rules["brute_force_threshold"]:
        alert = "Brute Force Attack Detected"
        logging.warning(alert)
        alert_list.append(alert)
        failed_login_attempts = 0
        return alert
    return None

# Function to simulate port scans
def simulate_port_scan():
    global ports_accessed
    ports_accessed += random.randint(1, 3)
    if ports_accessed >= rules["port_scan_threshold"]:
        alert = "Port Scan Detected"
        logging.warning(alert)
        alert_list.append(alert)
        ports_accessed = 0
        return alert
    return None

# Function to simulate suspicious IP access
def simulate_suspicious_ip_access():
    ip = random.choice(rules["suspicious_ip_list"])
    alert = f"Suspicious Access Detected from IP: {ip}"
    logging.warning(alert)
    alert_list.append(alert)
    return alert

# Phishing URL detection based on common characteristics
def is_phishing_url(url):
    # Check for suspicious keywords
    if any(keyword in url for keyword in rules["phishing_keywords"]):
        return True
    # Check for IP-based URLs (common in phishing)
    if re.match(r"http[s]?://\d+\.\d+\.\d+\.\d+", url):
        return True
    return False

# Function to simulate phishing attempts
def simulate_phishing_attempt():
    urls = [
        "http://example.com/login",
        "http://192.168.1.10/secure",
        "http://fake-bank.com/account_verify",
        "https://legit-site.com"
    ]
    url = random.choice(urls)
    if is_phishing_url(url):
        alert = f"Phishing Attempt Detected at URL: {url}"
        logging.warning(alert)
        alert_list.append(alert)
        return alert
    return None

# Function to detect anomalies using K-means clustering
def detect_anomalies():
    global request_data

    # Convert IP addresses to numerical format (for simplicity)
    numerical_data = [[hash(ip), ports, rate] for ip, ports, rate in request_data]

    # Scale data for clustering
    if len(numerical_data) > 2:  # Ensure we have enough data points
        scaled_data = scaler.fit_transform(numerical_data)
        kmeans.fit(scaled_data)

        # Predict clusters and identify anomalies
        clusters = kmeans.predict(scaled_data)
        for i, cluster in enumerate(clusters):
            if cluster == 1:  # Assuming cluster 1 is the anomalous cluster
                ip, ports, rate = request_data[i]
                alert = f"Anomalous Access Pattern Detected from IP: {ip}"
                logging.warning(alert)
                alert_list.append(alert)
                return alert
    
    # Reset request data for the next detection cycle
    request_data = []
    return None

# Function to generate request data for anomaly detection
def generate_request_data():
    ip = random.choice(["192.168.1.10", "10.0.0.5", "172.16.0.8", "203.0.113.1"])
    port_accesses = random.randint(1, 20)
    request_rate = random.uniform(0.5, 5.0)  # requests per second

    request_data.append([ip, port_accesses, request_rate])
    return [ip, port_accesses, request_rate]

# IDS simulation function with added phishing detection
def run_simulation():
    while True:
        attack_type = random.choice(['brute_force', 'port_scan', 'suspicious_ip', 'phishing', 'anomaly'])
        if attack_type == 'brute_force':
            simulate_brute_force()
        elif attack_type == 'port_scan':
            simulate_port_scan()
        elif attack_type == 'suspicious_ip':
            simulate_suspicious_ip_access()
        elif attack_type == 'phishing':
            simulate_phishing_attempt()
        elif attack_type == 'anomaly':
            generate_request_data()
            detect_anomalies()

        time.sleep(random.randint(1, 5))

# Start the IDS simulation in a separate thread
threading.Thread(target=run_simulation, daemon=True).start()

# Route to serve the main live view page
@app.route("/")
def index():
    return render_template("index.html")

# API endpoint to get recent logs for live view
@app.route("/get_logs")
def get_logs():
    with open(rules['log_file'], "r") as f:
        logs = f.readlines()
    return jsonify(logs[-10:])

# API endpoint to generate a report of the IDS activity
@app.route("/generate_report")
def generate_report():
    with open(rules['log_file'], "r") as file:
        logs = file.readlines()

    brute_force_count = sum(1 for log in logs if "Brute force attack detected" in log)
    port_scan_count = sum(1 for log in logs if "Port scanning detected" in log)
    suspicious_ip_count = sum(1 for log in logs if "Suspicious access detected" in log)
    phishing_count = sum(1 for log in logs if "Phishing attempt detected" in log)
    anomaly_count = sum(1 for log in logs if "Anomalous access pattern detected" in log)

    report = {
        "Brute Force Attacks": brute_force_count,
        "Port Scans": port_scan_count,
        "Suspicious IP Accesses": suspicious_ip_count,
        "Phishing Attempts": phishing_count,
        "Anomalous Patterns": anomaly_count
    }
    
    return jsonify(report)

# API endpoint to get real-time alerts for live view
@app.route("/get_alerts")
def get_alerts():
    return jsonify(alert_list[-5:])  # Get the last 5 alerts

# Start the Flask app in debug mode
if __name__ == "__main__":
    app.run(debug=True, port=5050)
