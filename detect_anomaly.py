from collections import defaultdict, deque
from datetime import timedelta
import math
from utils import get_asset_entity, entity_to_string

WINDOW = timedelta(minutes=5)
ALERT_COOLDOWN = timedelta(minutes=10)

def run(events):
    event_alerts = []
    store = defaultdict(deque)
    
    last_alert_time = defaultdict(lambda: defaultdict(lambda: None))
    
    for e in events:
        t = e["time"]
        
        entity = get_asset_entity(e)
        entity_str = entity_to_string(entity)
        
        store[entity_str].append(e)
        while store[entity_str] and t - store[entity_str][0]["time"] > WINDOW:
            store[entity_str].popleft()
        
        window_events = list(store[entity_str])
        
        if len(window_events) < 5:
            continue
        
        weighted_score = sum(
            math.exp(-(t - x["time"]).total_seconds() / 60)
            for x in window_events
        )
        
        normalization_factor = len(window_events) / 5
        multiplier = weighted_score / normalization_factor if normalization_factor > 0 else 0
        
        last_alert = last_alert_time[entity_str].get("TIME_WEIGHTED_BURST")
        cooldown_ok = last_alert is None or (t - last_alert) > ALERT_COOLDOWN
        
        if multiplier > 2.5 and cooldown_ok:
            if multiplier >= 5:
                weight = 30
            elif multiplier >= 4:
                weight = 25
            elif multiplier >= 3:
                weight = 20
            else:
                weight = 15
            
            event_alerts.append({
                "alert_id": f"BURST_{entity_str}_{t.isoformat()}",
                "time": t,
                "entity": entity,
                "entity_str": entity_str,
                "type": "ANOMALY",
                "name": "TIME_WEIGHTED_BURST",
                "severity": "MEDIUM",
                "weight": weight,
                "evidence": {
                    "weighted_activity_score": round(weighted_score, 2),
                    "normalization_factor": round(normalization_factor, 2),
                    "burst_intensity": f"{round(multiplier, 2)}x normal",
                    "event_count_in_window": len(window_events),
                    "window_minutes": 5
                },
                "source_events": window_events.copy()
            })
            last_alert_time[entity_str]["TIME_WEIGHTED_BURST"] = t
        
        event_types = {x["type"] for x in window_events}
        
        last_alert = last_alert_time[entity_str].get("CROSS_SURFACE_ACTIVITY")
        cooldown_ok = last_alert is None or (t - last_alert) > ALERT_COOLDOWN
        
        if len(event_types) >= 3 and cooldown_ok:
            if len(event_types) >= 4:
                weight = 25
            else:
                weight = 20
            
            event_alerts.append({
                "alert_id": f"LATERAL_{entity_str}_{t.isoformat()}",
                "time": t,
                "entity": entity,
                "entity_str": entity_str,
                "type": "ANOMALY",
                "name": "CROSS_SURFACE_ACTIVITY",
                "severity": "MEDIUM",
                "weight": weight,
                "evidence": {
                    "systems_accessed": sorted(list(event_types)),
                    "access_diversity": f"{len(event_types)} different systems",
                    "total_events": len(window_events),
                    "window_minutes": 5
                },
                "source_events": window_events.copy()
            })
            last_alert_time[entity_str]["CROSS_SURFACE_ACTIVITY"] = t
    
    return event_alerts
