from collections import defaultdict
import matplotlib.pyplot as plt
from datetime import timedelta
import numpy as np

SIGNAL_NAMES = {
    "WEB_BRUTE_FORCE": "Web Brute Force",
    "FW_PORT_SCAN": "Port Scan",
    "SSH_BRUTE_FORCE": "SSH Brute Force",
    "WIN_BRUTE_FORCE": "Windows Brute Force",
    "TIME_WEIGHTED_BURST": "Activity Burst",
    "CROSS_SURFACE_ACTIVITY": "Multi-System Access"
}

def choose(prompt, options):
    print("\n" + prompt)
    for k, v in options.items():
        print(f"[{k}] {v}")
    while True:
        c = input("> ").strip()
        if c in options:
            return c
        print("Invalid choice.")

def show_events(event_alerts, detail, all_events):
    print("\n" + "=" * 80)
    print("EVENT-BASED ALERT VIEW")
    print("=" * 80 + "\n")
    
    sorted_alerts = sorted(event_alerts, 
                          key=lambda x: (x["weight"], x["time"]), 
                          reverse=True)
    
    for idx, alert in enumerate(sorted_alerts, 1):
        readable_name = SIGNAL_NAMES.get(alert["name"], alert["name"])
        entity = alert['entity']
        entity_display = f"{entity['type'].upper()}:{entity['value']}"
        
        if detail == "1":
            print(f"{idx}. [{alert['severity']}] {readable_name}")
            print(f"    Entity: {entity_display} | Score: {alert['weight']} | Type: {alert['type']}")
            print(f"    Time: {alert['time']}\n")
        else:
            print("-" * 80)
            print(f"Alert #{idx} | ID: {alert['alert_id']}")
            print(f"Type: {alert['type']} | Threat: {readable_name}")
            print(f"Entity: {entity_display} | Severity: {alert['severity']} | Weight: {alert['weight']}")
            print(f"Time: {alert['time']}")
            
            if "evidence" in alert:
                print("\nEvidence:")
                for key, val in alert['evidence'].items():
                    if key != "note":
                        print(f"  - {key.replace('_', ' ').title()}: {val}")
            print()
    
    print(f"Total alerts: {len(sorted_alerts)}")
    
    if detail == "2":
        anomaly_alerts = [a for a in sorted_alerts if a["type"] == "ANOMALY"]
        if anomaly_alerts:
            graph = choose(
                "\nView graph?",
                {"1": "Yes", "2": "No"}
            )
            if graph == "1":
                _show_event_graphs(anomaly_alerts, all_events)

def show_cases(case_alerts, detail, all_events):
    print("\n" + "=" * 80)
    print("CASE-BASED VIEW")
    print("=" * 80 + "\n")
    
    sorted_cases = sorted(case_alerts, key=lambda x: x["score"], reverse=True)
    
    for idx, case in enumerate(sorted_cases, 1):
        entity = case['entity']
        entity_display = f"{entity['type'].upper()}:{entity['value']}"
        
        rule_count = sum(1 for e in case["event_alerts"] if e["type"] == "RULE")
        anomaly_count = sum(1 for e in case["event_alerts"] if e["type"] == "ANOMALY")
        
        print("=" * 80)
        print(f"CASE #{idx} | SCORE: {case['score']}/100")
        print("=" * 80)
        print(f"Entity: {entity_display} | Severity: {case['severity']}")
        print(f"Duration: {case['first_seen']} to {case['last_seen']} ({case['duration_minutes']:.1f} min)")
        print(f"Detections: {len(case['event_alerts'])} ({rule_count} rule, {anomaly_count} anomaly)")
        
        if detail == "2":
            print("\n" + "-" * 80)
            print("Timeline:")
            
            for evt in sorted(case["event_alerts"], key=lambda x: x["time"]):
                name = SIGNAL_NAMES.get(evt["name"], evt["name"])
                print(f"  [{evt['time']}] {name} (w={evt['weight']})")
                
                if "evidence" in evt:
                    for key, val in list(evt['evidence'].items())[:2]:
                        if key != "note":
                            print(f"    {key}: {val}")
        
        print("\n")
    
    print(f"Total cases: {len(sorted_cases)}")
    
    high = sum(1 for c in sorted_cases if c["severity"] == "HIGH")
    medium = sum(1 for c in sorted_cases if c["severity"] == "MEDIUM")
    low = sum(1 for c in sorted_cases if c["severity"] == "LOW")
    print(f"Severity: HIGH={high}, MEDIUM={medium}, LOW={low}")
    
    if detail == "2" and sorted_cases:
        graph = choose(
            "\nView graph?",
            {"1": "Yes", "2": "No"}
        )
        if graph == "1":
            _show_case_graphs(sorted_cases)

def _show_event_graphs(anomaly_alerts, all_events):
    print("\nSelect anomaly:")
    
    menu = {}
    for idx, alert in enumerate(anomaly_alerts[:10], 1):
        name = SIGNAL_NAMES.get(alert["name"], alert["name"])
        entity = alert['entity']
        entity_display = f"{entity['type']}:{entity['value']}"
        menu[str(idx)] = f"{name} - {entity_display} (w={alert['weight']})"
    
    selection = choose("Select:", menu)
    selected = anomaly_alerts[int(selection) - 1]
    
    if selected["name"] == "TIME_WEIGHTED_BURST":
        _plot_burst(selected, all_events)
    elif selected["name"] == "CROSS_SURFACE_ACTIVITY":
        _plot_lateral(selected, all_events)

def _plot_burst(alert, all_events):
    entity_str = alert["entity_str"]
    entity = alert["entity"]
    detection_time = alert["time"]
    
    if entity["type"] == "ip":
        entity_events = [e for e in all_events if e.get("ip") == entity["value"]]
    elif entity["type"] == "host":
        entity_events = [e for e in all_events if e.get("host") == entity["value"]]
    else:
        print("Cannot resolve entity")
        return
    
    entity_events.sort(key=lambda x: x["time"])
    
    window_start = detection_time - timedelta(minutes=10)
    window_end = detection_time + timedelta(minutes=5)
    context_events = [e for e in entity_events if window_start <= e["time"] <= window_end]
    
    if not context_events:
        print("No events in window")
        return
    
    start_time = min(e["time"] for e in context_events)
    end_time = max(e["time"] for e in context_events)
    total_seconds = (end_time - start_time).total_seconds()
    
    if total_seconds < 120:
        print(f"Not enough data ({total_seconds:.0f}s, need 120s)")
        return
    
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 10), height_ratios=[2, 1])
    fig.suptitle(f'Burst Detection: {entity_str}', fontsize=12, fontweight='bold')
    
    interval_seconds = 30
    num_intervals = int(total_seconds / interval_seconds) + 1
    
    bar_times = []
    bar_counts = []
    
    for i in range(num_intervals):
        interval_start = start_time + timedelta(seconds=i * interval_seconds)
        interval_end = interval_start + timedelta(seconds=interval_seconds)
        
        count = sum(1 for e in context_events if interval_start <= e["time"] < interval_end)
        bar_times.append(i * interval_seconds)
        bar_counts.append(count)
    
    ax1.bar(bar_times, bar_counts, width=interval_seconds * 0.8, 
            alpha=0.7, color='steelblue', edgecolor='black', linewidth=0.5)
    
    detection_seconds = (detection_time - start_time).total_seconds()
    ax1.axvline(x=detection_seconds, color='red', linestyle='--', linewidth=2.5, label='Alert')
    
    ax1.set_ylabel('Events per 30s', fontsize=11)
    ax1.set_title('Event Count Over Time', fontsize=12)
    ax1.legend(loc='upper left')
    ax1.grid(True, alpha=0.3, axis='y')
    ax1.set_xlim(0, total_seconds)
    
    time_points = []
    weighted_scores = []
    norm_factors = []
    
    for t_offset in range(0, int(total_seconds) + 1, 15):
        current_time = start_time + timedelta(seconds=t_offset)
        
        window_start_t = current_time - timedelta(seconds=300)
        window_events = [e for e in context_events if window_start_t <= e["time"] <= current_time]
        
        if window_events:
            weighted_score = sum(
                np.exp(-(current_time - e["time"]).total_seconds() / 60)
                for e in window_events
            )
            
            norm_factor = len(window_events) / 5
            
            time_points.append(t_offset)
            weighted_scores.append(weighted_score)
            norm_factors.append(norm_factor)
    
    if not time_points:
        print("No weighted data")
        return
    
    ax2.plot(time_points, weighted_scores, linewidth=2.5, color='darkred', 
             label='Weighted Score', marker='o', markersize=4)
    
    ax2.plot(time_points, norm_factors, linewidth=2, color='green',
             linestyle='--', label='Norm Factor', alpha=0.7)
    
    ax2.axvline(x=detection_seconds, color='red', linestyle='--', linewidth=2.5)
    
    detection_idx = min(range(len(time_points)), 
                       key=lambda i: abs(time_points[i] - detection_seconds))
    detection_score = weighted_scores[detection_idx]
    detection_norm = norm_factors[detection_idx]
    
    multiplier = detection_score / detection_norm if detection_norm > 0 else 0
    
    ax2.annotate(f'Alert\n{multiplier:.1f}x',
                xy=(detection_seconds, detection_score),
                xytext=(detection_seconds + total_seconds * 0.05, detection_score * 1.1),
                fontsize=10, fontweight='bold',
                bbox=dict(boxstyle='round', facecolor='yellow', alpha=0.8),
                arrowprops=dict(arrowstyle='->', color='red', lw=1.5))
    
    ax2.set_xlabel('Time (seconds)', fontsize=11)
    ax2.set_ylabel('Score', fontsize=11)
    ax2.set_title('Weighted Activity vs Normalization', fontsize=12)
    ax2.legend(loc='upper left')
    ax2.grid(True, alpha=0.3)
    ax2.set_ylim(bottom=0)
    ax2.set_xlim(0, total_seconds)
    
    plt.tight_layout()
    plt.show()

def _plot_lateral(alert, all_events):
    entity_str = alert["entity_str"]
    entity = alert["entity"]
    detection_time = alert["time"]
    
    if entity["type"] == "ip":
        entity_events = [e for e in all_events if e.get("ip") == entity["value"]]
    elif entity["type"] == "host":
        entity_events = [e for e in all_events if e.get("host") == entity["value"]]
    else:
        print("Cannot resolve entity")
        return
    
    entity_events.sort(key=lambda x: x["time"])
    
    window_start = detection_time - timedelta(minutes=5)
    window_end = detection_time + timedelta(minutes=5)
    context_events = [e for e in entity_events if window_start <= e["time"] <= window_end]
    
    if not context_events:
        print("No events in window")
        return
    
    fig, ax = plt.subplots(figsize=(14, 7))
    fig.suptitle(f'Multi-System Access: {entity_str}', fontsize=12, fontweight='bold')
    
    start_time = min(e["time"] for e in context_events)
    
    system_types = ['web', 'firewall', 'ssh', 'windows', 'edr']
    colors = {'web': 'steelblue', 'firewall': 'purple', 'ssh': 'orange',
              'windows': 'darkred', 'edr': 'green'}
    
    y_positions = {st: idx for idx, st in enumerate(system_types)}
    
    for e in context_events:
        etype = e["type"]
        if etype in system_types:
            seconds = (e["time"] - start_time).total_seconds()
            y_pos = y_positions[etype]
            
            ax.scatter(seconds, y_pos, s=120, alpha=0.8,
                      color=colors[etype], edgecolors='black', linewidths=1)
    
    detection_seconds = (detection_time - start_time).total_seconds()
    ax.axvline(x=detection_seconds, color='red', linestyle='--', linewidth=2.5, label='Alert')
    
    systems_accessed = alert.get("evidence", {}).get("systems_accessed", [])
    num_systems = len(systems_accessed)
    
    ax.annotate(f'{num_systems} systems',
               xy=(detection_seconds, len(system_types)/2),
               xytext=(detection_seconds + 10, len(system_types)/2),
               fontsize=10, fontweight='bold',
               bbox=dict(boxstyle='round', facecolor='yellow', alpha=0.8),
               arrowprops=dict(arrowstyle='->', color='red', lw=1.5))
    
    ax.set_xlabel('Time (seconds)', fontsize=11)
    ax.set_ylabel('System Type', fontsize=11)
    ax.set_title('Multi-System Activity Timeline', fontsize=12)
    ax.set_yticks(range(len(system_types)))
    ax.set_yticklabels([st.upper() for st in system_types], fontsize=10)
    ax.grid(axis='x', alpha=0.3)
    ax.set_ylim(-0.5, len(system_types) - 0.5)
    ax.legend()
    
    plt.tight_layout()
    plt.show()

def _show_case_graphs(case_alerts):
    print("\nSelect case:")
    
    menu = {}
    for idx, case in enumerate(case_alerts[:10], 1):
        entity = case['entity']
        entity_display = f"{entity['type']}:{entity['value']}"
        menu[str(idx)] = f"{entity_display} (score={case['score']})"
    
    selection = choose("Select:", menu)
    selected_case = case_alerts[int(selection) - 1]
    
    viz_choice = choose(
        "\nVisualization:",
        {
            "1": "Line Chart",
            "2": "Stacked Area"
        }
    )
    
    if viz_choice == "1":
        _plot_line(selected_case)
    else:
        _plot_stacked(selected_case)

def _plot_line(case):
    events = sorted(case["event_alerts"], key=lambda e: e["time"])
    
    if not events:
        print("No events")
        return
    
    fig, ax = plt.subplots(figsize=(14, 7))
    
    entity = case['entity']
    entity_display = f"{entity['type'].upper()}:{entity['value']}"
    fig.suptitle(f'Risk Escalation: {entity_display} (Score: {case["score"]})', fontsize=12, fontweight='bold')
    
    start_time = events[0]["time"]
    
    times = []
    cumulative = []
    current = 0
    
    for evt in events:
        minutes = (evt["time"] - start_time).total_seconds() / 60
        current += evt["weight"]
        times.append(minutes)
        cumulative.append(current)
    
    ax.plot(times, cumulative, linewidth=2.5, color='darkred', 
            label='Cumulative Risk', marker='o', markersize=6)
    
    for i, (t, score, evt) in enumerate(zip(times, cumulative, events)):
        name = SIGNAL_NAMES.get(evt["name"], evt["name"])
        ax.annotate(f'{name}\n+{evt["weight"]}',
                   xy=(t, score),
                   xytext=(5, 10 if i % 2 == 0 else -10),
                   textcoords='offset points',
                   fontsize=8,
                   bbox=dict(boxstyle='round', facecolor='white', alpha=0.8),
                   arrowprops=dict(arrowstyle='->', lw=0.8))
    
    ax.set_xlabel('Time (minutes)', fontsize=11)
    ax.set_ylabel('Cumulative Risk', fontsize=11)
    ax.set_title('Risk Timeline', fontsize=12)
    ax.legend()
    ax.grid(True, alpha=0.3)
    ax.set_ylim(bottom=0, top=max(cumulative) * 1.1)
    
    plt.tight_layout()
    plt.show()

def _plot_stacked(case):
    events = sorted(case["event_alerts"], key=lambda e: e["time"])
    
    if not events:
        print("No events")
        return
    
    fig, ax = plt.subplots(figsize=(14, 7))
    
    entity = case['entity']
    entity_display = f"{entity['type'].upper()}:{entity['value']}"
    fig.suptitle(f'Detection Contributions: {entity_display} (Score: {case["score"]})', fontsize=12, fontweight='bold')
    
    start_time = events[0]["time"]
    
    times = [0]
    burst = [0]
    lateral = [0]
    rules = [0]
    
    curr_burst = 0
    curr_lateral = 0
    curr_rules = 0
    
    for evt in events:
        minutes = (evt["time"] - start_time).total_seconds() / 60
        
        if evt["name"] == "TIME_WEIGHTED_BURST":
            curr_burst += evt["weight"]
        elif evt["name"] == "CROSS_SURFACE_ACTIVITY":
            curr_lateral += evt["weight"]
        elif evt["type"] == "RULE":
            curr_rules += evt["weight"]
        
        times.append(minutes)
        burst.append(curr_burst)
        lateral.append(curr_lateral)
        rules.append(curr_rules)
    
    ax.fill_between(times, 0, burst, alpha=0.7, color='steelblue', 
                    label='Burst', step='post')
    ax.fill_between(times, burst, [b + l for b, l in zip(burst, lateral)],
                    alpha=0.7, color='orange', label='Lateral', step='post')
    ax.fill_between(times, [b + l for b, l in zip(burst, lateral)],
                    [b + l + r for b, l, r in zip(burst, lateral, rules)],
                    alpha=0.7, color='green', label='Rules', step='post')
    
    ax.set_xlabel('Time (minutes)', fontsize=11)
    ax.set_ylabel('Risk Contribution', fontsize=11)
    ax.set_title('Detection Type Contributions', fontsize=12)
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.show()
