from collections import defaultdict, deque
from datetime import timedelta
from utils import get_actor_entity, entity_to_string

WEB_LOGIN_WINDOW = timedelta(minutes=2)
FW_WINDOW = timedelta(minutes=3)
SSH_WINDOW = timedelta(minutes=3)
WIN_WINDOW = timedelta(minutes=3)
ALERT_COOLDOWN = timedelta(minutes=10)

def run(events):
    event_alerts = []
    
    web_login = defaultdict(deque)
    fw_events = defaultdict(deque)
    ssh_events = defaultdict(deque)
    win_events = defaultdict(deque)
    
    last_alert_time = defaultdict(lambda: defaultdict(lambda: None))
    
    for e in events:
        ip = e.get("ip", "unknown")
        t = e["time"]
        
        entity = get_actor_entity(e)
        entity_str = entity_to_string(entity)
        
        if e["type"] == "web" and e["path"] == "/login":
            web_login[ip].append(e)
            
            while web_login[ip] and t - web_login[ip][0]["time"] > WEB_LOGIN_WINDOW:
                web_login[ip].popleft()
            
            failures = [x for x in web_login[ip] if x["status"] == 401]
            success = any(x["status"] == 200 for x in web_login[ip])
            
            last_alert = last_alert_time[entity_str].get("WEB_BRUTE_FORCE")
            cooldown_ok = last_alert is None or (t - last_alert) > ALERT_COOLDOWN
            
            if len(failures) >= 6 and not success and cooldown_ok:
                weight = 35 + min(len(failures) - 6, 10)
                
                event_alerts.append({
                    "alert_id": f"WEB_BRUTE_{entity_str}_{t.isoformat()}",
                    "time": t,
                    "entity": entity,
                    "entity_str": entity_str,
                    "type": "RULE",
                    "name": "WEB_BRUTE_FORCE",
                    "severity": "HIGH",
                    "weight": weight,
                    "evidence": {
                        "failure_attempts": len(failures),
                        "target_path": e["path"],
                        "timeframe_minutes": 2,
                        "window_start": web_login[ip][0]["time"].isoformat(),
                        "window_end": t.isoformat()
                    },
                    "source_events": list(web_login[ip])
                })
                last_alert_time[entity_str]["WEB_BRUTE_FORCE"] = t
        
        if e["type"] == "firewall":
            fw_events[ip].append(e)
            
            while fw_events[ip] and t - fw_events[ip][0]["time"] > FW_WINDOW:
                fw_events[ip].popleft()
            
            denied_ports = {x["port"] for x in fw_events[ip] if x["action"] == "deny"}
            
            last_alert = last_alert_time[entity_str].get("FW_PORT_SCAN")
            cooldown_ok = last_alert is None or (t - last_alert) > ALERT_COOLDOWN
            
            if len(denied_ports) >= 3 and cooldown_ok:
                weight = 30 + min(len(denied_ports) - 3, 15)
                
                event_alerts.append({
                    "alert_id": f"FW_SCAN_{entity_str}_{t.isoformat()}",
                    "time": t,
                    "entity": entity,
                    "entity_str": entity_str,
                    "type": "RULE",
                    "name": "FW_PORT_SCAN",
                    "severity": "HIGH",
                    "weight": weight,
                    "evidence": {
                        "unique_ports_scanned": sorted(list(denied_ports)),
                        "total_attempts": len(fw_events[ip]),
                        "timeframe_minutes": 3,
                        "window_start": fw_events[ip][0]["time"].isoformat(),
                        "window_end": t.isoformat()
                    },
                    "source_events": list(fw_events[ip])
                })
                last_alert_time[entity_str]["FW_PORT_SCAN"] = t
        
        if e["type"] == "ssh" and e.get("outcome") == "fail":
            ssh_events[ip].append(e)
            
            while ssh_events[ip] and t - ssh_events[ip][0]["time"] > SSH_WINDOW:
                ssh_events[ip].popleft()
            
            last_alert = last_alert_time[entity_str].get("SSH_BRUTE_FORCE")
            cooldown_ok = last_alert is None or (t - last_alert) > ALERT_COOLDOWN
            
            if len(ssh_events[ip]) >= 4 and cooldown_ok:
                weight = 35 + min(len(ssh_events[ip]) - 4, 10)
                
                targeted_users = list({x.get("user") for x in ssh_events[ip] if x.get("user")})
                
                event_alerts.append({
                    "alert_id": f"SSH_BRUTE_{entity_str}_{t.isoformat()}",
                    "time": t,
                    "entity": entity,
                    "entity_str": entity_str,
                    "type": "RULE",
                    "name": "SSH_BRUTE_FORCE",
                    "severity": "HIGH",
                    "weight": weight,
                    "evidence": {
                        "failed_attempts": len(ssh_events[ip]),
                        "targeted_usernames": targeted_users,
                        "timeframe_minutes": 3,
                        "window_start": ssh_events[ip][0]["time"].isoformat(),
                        "window_end": t.isoformat()
                    },
                    "source_events": list(ssh_events[ip])
                })
                last_alert_time[entity_str]["SSH_BRUTE_FORCE"] = t
        
        if e["type"] == "windows" and e["event"] == 4625:
            win_events[ip].append(e)
            
            while win_events[ip] and t - win_events[ip][0]["time"] > WIN_WINDOW:
                win_events[ip].popleft()
            
            last_alert = last_alert_time[entity_str].get("WIN_BRUTE_FORCE")
            cooldown_ok = last_alert is None or (t - last_alert) > ALERT_COOLDOWN
            
            if len(win_events[ip]) >= 5 and cooldown_ok:
                weight = 35 + min(len(win_events[ip]) - 5, 10)
                
                event_alerts.append({
                    "alert_id": f"WIN_BRUTE_{entity_str}_{t.isoformat()}",
                    "time": t,
                    "entity": entity,
                    "entity_str": entity_str,
                    "type": "RULE",
                    "name": "WIN_BRUTE_FORCE",
                    "severity": "HIGH",
                    "weight": weight,
                    "evidence": {
                        "failed_logons": len(win_events[ip]),
                        "target_host": e.get("host"),
                        "target_user": e.get("user"),
                        "timeframe_minutes": 3,
                        "window_start": win_events[ip][0]["time"].isoformat(),
                        "window_end": t.isoformat()
                    },
                    "source_events": list(win_events[ip])
                })
                last_alert_time[entity_str]["WIN_BRUTE_FORCE"] = t
    
    return event_alerts
