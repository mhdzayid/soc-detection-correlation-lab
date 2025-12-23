import re
from datetime import datetime

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

def parse_iso_time(ts: str):
    try:
        return datetime.fromisoformat(ts.replace("Z", ""))
    except Exception:
        return None

def parse_syslog_time(month_str: str, day_str: str, time_str: str, assumed_year: int = 2025):
    try:
        month = MONTHS[month_str]
        day = int(day_str)
        hh, mm, ss = time_str.split(":")
        return datetime(assumed_year, month, day, int(hh), int(mm), int(ss))
    except Exception:
        return None

WEB_RE = re.compile(
    r'^(?P<time>\S+)\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<method>GET|POST)\s+(?P<path>/\S+)\s+(?P<status>\d{3})\s+(?P<bytes>\d+)\s+(?P<ua>.+)$'
)

FW_KV_RE = re.compile(r'(\w+)=([^\s]+)')

WIN_RE = re.compile(
    r'^(?P<time>\S+),(?P<event>\d+),(?P<host>[^,]+),(?P<user>[^,]+),(?P<ip>[^,]+),(?P<rest>.*)$'
)

SSH_FROM_RE = re.compile(r'\bfrom\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\b')
SSH_ACCEPT_RE = re.compile(r'Accepted\s+(?P<method>\w+)\s+for\s+(?P<user>\S+)')
SSH_FAIL_RE = re.compile(r'Failed\s+password\s+for\s+(invalid\s+user\s+)?(?P<user>\S+)')

EDR_RE = re.compile(
    r'^(?P<time>\S+)\s+(?P<host>\S+)\s+(?P<etype>ProcessCreate|NetworkConnect|FileCreate|RegistrySet)\s+(?P<process>\S+)\s+(?P<parent>\S+)\s+(?P<user>\S+)\s+"(?P<detail>.*)"$'
)

def extract_identities(evt: dict):
    actor = evt.get("ip") or evt.get("user")
    asset = evt.get("host")
    return actor, asset

def get_actor_entity(evt: dict):
    ip = evt.get("ip")
    user = evt.get("user")
    
    if ip and ip != "unknown":
        return {"type": "ip", "value": ip, "role": "actor"}
    elif user and user != "unknown":
        return {"type": "user", "value": user, "role": "actor"}
    else:
        return {"type": "unknown", "value": "unknown", "role": "actor"}

def get_asset_entity(evt: dict):
    host = evt.get("host")
    ip = evt.get("ip")
    
    if host and host != "unknown":
        return {"type": "host", "value": host, "role": "asset"}
    elif ip and ip != "unknown":
        return {"type": "ip", "value": ip, "role": "asset"}
    else:
        return {"type": "unknown", "value": "unknown", "role": "asset"}

def entity_to_string(entity: dict) -> str:
    return f"{entity['type']}:{entity['value']}"

def parse_log(line: str):
    line = line.strip()
    if not line:
        return None

    m = WEB_RE.match(line)
    if m:
        t = parse_iso_time(m.group("time"))
        if not t:
            return None
        return {
            "type": "web",
            "time": t,
            "ip": m.group("ip"),
            "method": m.group("method"),
            "path": m.group("path"),
            "status": int(m.group("status")),
            "bytes": int(m.group("bytes")),
            "ua": m.group("ua"),
            "raw": line
        }

    if "action=" in line and "src=" in line and "dpt=" in line:
        ts = line.split()[0]
        t = parse_iso_time(ts)
        if not t:
            return None

        parts = {}
        for k, v in FW_KV_RE.findall(line):
            parts[k] = v

        return {
            "type": "firewall",
            "time": t,
            "ip": parts.get("src"),
            "src": parts.get("src"),
            "dst": parts.get("dst"),
            "action": parts.get("action"),
            "port": int(parts.get("dpt", "0")),
            "proto": parts.get("proto"),
            "reason": parts.get("reason"),
            "raw": line
        }

    m = WIN_RE.match(line)
    if m:
        t = parse_iso_time(m.group("time"))
        if not t:
            return None
        return {
            "type": "windows",
            "time": t,
            "event": int(m.group("event")),
            "host": m.group("host"),
            "user": m.group("user"),
            "ip": m.group("ip"),
            "raw": line
        }

    parts = line.split()
    if len(parts) >= 5 and parts[0] in MONTHS and parts[1].isdigit() and re.match(r'^\d{2}:\d{2}:\d{2}$', parts[2]):
        month, day, hhmmss = parts[0], parts[1], parts[2]
        host = parts[3]
        t = parse_syslog_time(month, day, hhmmss, assumed_year=2025)
        if not t:
            return None

        src_ip = None
        ipm = SSH_FROM_RE.search(line)
        if ipm:
            src_ip = ipm.group("ip")

        ssh_user = None
        outcome = None
        auth_method = None

        am = SSH_ACCEPT_RE.search(line)
        if am:
            outcome = "success"
            auth_method = am.group("method")
            ssh_user = am.group("user")

        fm = SSH_FAIL_RE.search(line)
        if fm:
            outcome = "fail"
            ssh_user = fm.group("user")

        if "sshd" in line:
            return {
                "type": "ssh",
                "time": t,
                "host": host,
                "ip": src_ip,
                "user": ssh_user,
                "outcome": outcome,
                "auth_method": auth_method,
                "raw": line
            }

    m = EDR_RE.match(line)
    if m:
        t = parse_iso_time(m.group("time"))
        if not t:
            return None
        return {
            "type": "edr",
            "time": t,
            "host": m.group("host"),
            "ip": None,
            "etype": m.group("etype"),
            "process": m.group("process"),
            "parent": m.group("parent"),
            "user": m.group("user"),
            "detail": m.group("detail"),
            "raw": line
        }

    return None