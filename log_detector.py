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
        for i in range(len(attempts) - THRESHOLD + 1):
            window = attempts[i:i + THRESHOLD]
            time_diff = (window[-1] - window[0]).total_seconds()
            if time_diff <= TIMEWINDOW:
                j = i + THRESHOLD
                while j < len(attempts) and (attempts[j] - attempts[i]).total_seconds() <= TIMEWINDOW:
                    j += 1
                window = attempts[i:j]
                alerts.append((ip, len(window), int((window[-1] - window[0]).total_seconds())))
                break

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
        severity = "Critical" if count >= 20 else "High" if count >= 10 else "Medium"
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
    
