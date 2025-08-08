import os
import re

LOG_PATH = "logs/auth.log"

SUSPICIOUS_PATTERNS = [
    r"unauthorized",
    r"failed password",
    r"invalid user",
    r"suspicious input",
    r"error"
]

def load_logs(log_path):
    if not os.path.exists(log_path):
        print(f"[!] Log file not found at: {log_path}")
        return []
    with open(log_path, "r") as file:
        return file.readlines()

def find_suspicious_entries(log_lines):
    flagged = []
    for line in log_lines:
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                flagged.append(line.strip())
                break
    return flagged

def alert(flagged_entries):
    if flagged_entries:
        print("\n[!] Suspicious activity detected:")
        for entry in flagged_entries:
            print(f"- {entry}")
    else:
        print("[✓] No suspicious entries found.")

def main():
    print("[*] Parsing log file...")
    logs = load_logs(LOG_PATH)
    flagged = find_suspicious_entries(logs)
    alert(flagged)

if __name__ == "__main__":
    main()

