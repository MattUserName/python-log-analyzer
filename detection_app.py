# Log Analysis Script
# Detect repeated failed login attempts

THRESHOLD = 5

log_file = "auth.log"
failed_attempts = {}

with open(log_file, "r") as file:
    for line in file:
        if "Failed login" in line:
            parts = line.split("from ")
            ip_address = parts[1].strip()

            if ip_address in failed_attempts:
                failed_attempts[ip_address] += 1
            else:
                failed_attempts[ip_address] = 1

print("Failed Login Summary:")
for ip, count in failed_attempts.items():
    print(f"{ip} -> {count} failed attempts")

    if count >= THRESHOLD:
        print(f"ALERT: Possible brute-force attack detectedd from {ip}")
        
