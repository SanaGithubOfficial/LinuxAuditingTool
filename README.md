# Linux Auditing Tools

A collection of Python-based Linux system auditing tools for checking user activity, suspicious processes, system logs, and configuration issues. 
Useful for system administrators and SOC analysts.

##  Features

- Analyze system logs (auth.log, syslog)
- Detect new user accounts and sudoers
- Check for suspicious processes and services
- Monitor file permission anomalies
- Summarize system health and potential risks

##  Getting Started

### Prerequisites

- Linux system (Ubuntu/Debian preferred)
- Python 3.x
- Root or sudo access
- create a folder in /root with name ~/linux_audit_tool and create more three folders in it by name /logs, /scripts, /reports

### Installation

```bash
cd linux-auditing-tools
python3 network_audit.py
