# Log Analysis Script
# Detect repeated failed login attempts

from datetime import datetime
import csv

log_file = "auth.log"

THRESHOLD = 5
TIMEWINDOW = 120

CSV_REPORT = "incident_report.csv"
TXT_REPORT = "security_report.txt"

failed_logins = {}

with open(log_file, "r") as file:
    for line in file:
        if "Failed login" in line:

            parts = line.split()
            timestamp = parts[0] + " " + parts[1]
            ip = parts[-1]

            time_obj = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

            if ip not in failed_logins:
                failed_logins[ip] = []

            failed_logins[ip].append(time_obj)

alerts = []

for ip, attempts in failed_logins.items():

    attempts.sort()
    
    if len(attempts) >= THRESHOLD:
        first_attempt = attempts[0]
        last_attempt = attempts[-1]

        time_diff = (last_attempt - first_attempt).seconds

        if time_diff <= TIMEWINDOW:
            alerts.append((ip, len(attempts), time_diff))

print("\nSecurity Alerts:")

if not alerts:
    print("No suspicious activity detected.")

for ip, count, seconds in alerts:
    print("+++++++++++++++++++++++++++++")
    print("Suspicious activity detected!")
    print("+++++++++++++++++++++++++++++")
    print(f"IP Address: {ip}")
    print(f"Failed Attempts: {count}")
    print(f"Time Window: {seconds} seconds\n")

with open(CSV_REPORT, "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow([
        "IP Address",
        "Failed Attempts",
        "Time Window (seconds)",
        "Severity"
    ])

    for ip, count, seconds in alerts:
        severity ="High" if count >= 5 else "Medium"
        writer.writerow([ip, count, seconds, severity])
        

with open(TXT_REPORT, "w") as report:
    report.write("Security Alert Report\n")
    report.write("=====================\n")

    for ip, count, seconds in alerts:
        report.write(f"{ip} -> {count} attempts in {seconds} seconds\n")

print(f"\nTotal Alerts Detected: {len(alerts)}")
print("\nFailed Login Activity Summary (All IPs)")

if not failed_logins:
    print("No failed login activity found in logs.")
else:
    sorted_ips = sorted(
        failed_logins.items(),
        key=lambda x: len(x[1]),
        reverse=True
    )

for ip, attempts in sorted_ips:
    print(f"{ip} -> {len(attempts)} failed attempts")
    
