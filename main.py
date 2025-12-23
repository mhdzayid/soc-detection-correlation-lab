from utils import parse_log
from detect_rules import run as run_rules
from detect_anomaly import run as run_anomaly
from correlate import correlate
from ui import choose, show_events, show_cases

events = []
with open("logs.txt") as f:
    for line in f:
        evt = parse_log(line)
        if evt and evt.get("time"):
            events.append(evt)

print(f"[INFO] Loaded {len(events)} events")

rule_alerts = run_rules(events)
anomaly_alerts = run_anomaly(events)

all_event_alerts = rule_alerts + anomaly_alerts

print(f"[INFO] Generated {len(all_event_alerts)} alerts")
print(f"       Rule: {len(rule_alerts)}, Anomaly: {len(anomaly_alerts)}")

case_alerts = correlate(all_event_alerts)

print(f"[INFO] Correlated into {len(case_alerts)} cases")

mode = choose(
    "Select mode:",
    {
        "1": "Event-based alerts",
        "2": "Case-based view"
    }
)

detail = choose(
    "Detail level:",
    {
        "1": "Summary",
        "2": "Detailed"
    }
)

if mode == "1":
    show_events(all_event_alerts, detail, events)
else:
    show_cases(case_alerts, detail, events)

print("\n[INFO] Analysis complete")
