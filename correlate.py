def correlate(event_alerts):
    entity_cases = {}
    
    for event in event_alerts:
        entity_str = event["entity_str"]
        
        if entity_str not in entity_cases:
            entity_cases[entity_str] = {
                "entity": event["entity"],
                "entity_str": entity_str,
                "event_alerts": [],
                "first_seen": event["time"],
                "last_seen": event["time"]
            }
        
        entity_cases[entity_str]["event_alerts"].append(event)
        
        if event["time"] < entity_cases[entity_str]["first_seen"]:
            entity_cases[entity_str]["first_seen"] = event["time"]
        if event["time"] > entity_cases[entity_str]["last_seen"]:
            entity_cases[entity_str]["last_seen"] = event["time"]
    
    case_alerts = []
    
    for entity_str, case in entity_cases.items():
        events = case["event_alerts"]
        
        unique_detections = {}
        for evt in events:
            name = evt["name"]
            if name not in unique_detections or evt["weight"] > unique_detections[name]["weight"]:
                unique_detections[name] = evt
        
        deduped_events = list(unique_detections.values())
        
        base_score = sum(e["weight"] for e in deduped_events)
        
        unique_names = set(e["name"] for e in deduped_events)
        has_rule = any(e["type"] == "RULE" for e in deduped_events)
        has_anomaly = any(e["type"] == "ANOMALY" for e in deduped_events)
        
        bonus = 0
        
        if has_rule and has_anomaly:
            bonus += 15
        
        if len(unique_names) >= 4:
            bonus += 10
        elif len(unique_names) >= 3:
            bonus += 5
        
        final_score = min(base_score + bonus, 100)
        
        if final_score >= 80:
            severity = "HIGH"
        elif final_score >= 70 and len(unique_names) >= 3:
            severity = "HIGH"
        elif final_score >= 60 and has_rule and has_anomaly:
            severity = "HIGH"
        elif final_score >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        case_alerts.append({
            "entity": case["entity"],
            "entity_str": entity_str,
            "severity": severity,
            "score": final_score,
            "event_alerts": deduped_events,
            "all_events": events,
            "first_seen": case["first_seen"],
            "last_seen": case["last_seen"],
            "duration_minutes": (case["last_seen"] - case["first_seen"]).total_seconds() / 60,
            "attack_metrics": {
                "unique_detection_types": len(unique_names),
                "has_rule_based": has_rule,
                "has_anomaly_based": has_anomaly,
                "total_detections": len(events),
                "unique_detections": len(deduped_events),
                "bonus_applied": bonus
            }
        })
    
    return case_alerts
