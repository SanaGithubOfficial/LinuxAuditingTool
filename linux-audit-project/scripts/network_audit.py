#!/usr/bin/env python3

import subprocess
import datetime
import os

# Setup paths
report_dir = os.path.expanduser("~/linux-audit-project/reports")
os.makedirs(report_dir, exist_ok=True)
report_path = os.path.join(report_dir, "day2_network_audit.txt")

timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def run(cmd):
    """Run a shell command and return output or error."""
    print(f"\n>>> Running: {cmd}")
    try:
        return subprocess.check_output(cmd, shell=True, text=True).strip()
    except subprocess.CalledProcessError as e:
        return f"[ERROR] Command failed: {cmd}\n{e.output}"

# --------- Start Audit ---------
report = f"# Kali Linux Security Audit Report\nGenerated: {timestamp}\n\n"

# 1. System Information
report += "\nSystem Info:\n"
sysinfo = run("hostnamectl") + "\n" + run("uname -a")
report += sysinfo + "\n"

# 2. UFW Firewall
ufw_output = run("sudo ufw status verbose")
report += "\n UFW Firewall Status:\n" + ufw_output + "\n"
if "inactive" in ufw_output.lower():
    report += "[Suggestion] UFW is inactive. Enable with:\n  sudo ufw enable\n"

# 3. iptables
iptables_output = run("sudo iptables -L -n -v")
report += "\niptables Rules:\n" + iptables_output + "\n"
if "policy accept" in iptables_output.lower():
    report += "[Suggestion] iptables INPUT policy is ACCEPT. Set it to DROP and allow only necessary ports:\n"
    report += "  sudo iptables -P INPUT DROP\n  sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT\n"

# 4. Open Ports
ports_output = run("ss -tuln")
report += "\n Open Ports (ss -tuln):\n" + ports_output + "\n"
if ":21" in ports_output or ":23" in ports_output:
    report += "[Suggestion] Port 21 (FTP) or 23 (Telnet) open — disable or replace with secure alternatives:\n"
    report += "  sudo systemctl disable --now vsftpd\n  sudo apt purge telnet -y\n"

# 5. Active Network Services
services_output = run("sudo systemctl list-units --type=service --state=running | grep -Ei 'network|ssh|http|ftp|vpn|firewalld'")
report += "\nActive Network Services:\n" + services_output + "\n"
if "ftp" in services_output.lower() or "telnet" in services_output.lower():
    report += "[Suggestion] Insecure services running (FTP/Telnet). Use SSH/SFTP instead:\n"
    report += "  sudo apt purge ftp telnet -y\n"

# 6. Rootkit Detection (chkrootkit)
chkrootkit_output = run("sudo chkrootkit")
report += "\nRootkit Check (chkrootkit):\n" + chkrootkit_output + "\n"
if "infected" in chkrootkit_output.lower() or "suspicious" in chkrootkit_output.lower():
    report += "[ALERT] Rootkit signs found. Investigate with rkhunter and consider offline scanning.\n"

# 7. Lynis System Hardening
lynis_output = run("sudo lynis audit system --quick | grep -Ei 'hardening index|suggestion|warning'")
report += "\nSystem Hardening (lynis summary):\n" + lynis_output + "\n"
if "hardening index" in lynis_output.lower():
    try:
        index = int([s for s in lynis_output.split() if s.isdigit()][0])
        if index < 60:
            report += "[Suggestion] Low hardening index. Review Lynis suggestions to improve your security posture.\n"
    except:
        report += "[Suggestion] Could not determine hardening index score.\n"

# --------- End of Report ---------
with open(report_path, "w") as f:
    f.write(report)

print(f"\nAudit complete. Report saved to:\n{report_path}")
