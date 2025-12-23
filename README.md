# soc-detection-correlation-lab

**SOC Detection & Correlation Fundamentals**

---

## Project Objective

The objective of this project is to demonstrate **core SOC detection and correlation principles**, focusing on how multiple detection techniques are used together rather than relying on a single alerting method.

This project is intentionally **educational**, not production-grade.  
It is designed to deepen understanding of how SOCs actually work internally — mechanics that are often hidden behind enterprise tools.

The emphasis is on:

- How individual detections generate **partial, low-confidence signals**
- Why single detections are insufficient on their own
- How correlation adds context and turns alerts into investigations

This project avoids novelty or automation claims and instead focuses on **foundational SOC concepts** that apply across tools and platforms.

---

## Detection Approaches Implemented

This project implements **two complementary detection approaches**, each covering different blind spots.

### 1. Rule-Based Detection  
Implemented in `detect_rules.py`

Rule-based detections identify **explicit, known attack behaviors**, including:

- Web login brute force attempts  
- SSH brute force activity  
- Firewall port scanning  
- Windows authentication failures  

**Strength:** Precise and reliable  
**Limitation:** Narrow and context-limited

---

### 2. Anomaly-Based Detection  
Implemented in `detect_anomaly.py`

Anomaly-based detections identify **behavioral deviations**, including:

- Time-weighted activity bursts  
- Cross-surface activity across multiple systems  

**Strength:** Broad visibility  
**Limitation:** Noisy when used alone

---

### Why Correlation Matters

This project demonstrates that:

- Rule-based detections provide **strong but narrow** signals  
- Anomaly-based detections provide **weak but broad** signals  
- Correlation combines them to create **investigation-ready context**

Correlation does not replace detections — it **connects them**.

---

## Detection & Correlation Pipeline

```mermaid
graph TD
    A[logs.txt] --> B[utils.py<br/>Parsing & Normalization]
    B --> C{Detection Engines}
    C --> D[detect_rules.py<br/>Rule-Based]
    C --> E[detect_anomaly.py<br/>Anomaly-Based]
    D --> F[correlate.py<br/>Correlation & Scoring]
    E --> F
    F --> G[ui.py<br/>Visualization]
    G --> H[main.py]

