# Intrusion Detection System (IDS)

A hybrid network intrusion detection system that combines machine learning models with legacy rule-based detection to identify and alert on suspicious network traffic patterns.

## Overview

This IDS monitors network traffic in real-time, analyzes packet features, and detects anomalies using:
- **Machine Learning**: Random Forest model with scikit-learn preprocessing
- **Rule-Based Detection**: 23 predefined attack patterns (SYN floods, port scans, buffer overflows, etc.)
- **Real-Time Alerting**: Immediate console and file-based alert logging

## Features

- 🔍 **Packet Capture & Analysis**: Captures live network traffic using Scapy
- 🤖 **ML-Based Detection**: Uses Random Forest model for anomaly detection
- ⚙️ **Rule Engine**: Detects known attack signatures (Neptune, Smurf, Teardrop, LAND, Nmap, Satan, etc.)
- 📊 **Traffic Metrics**: Analyzes packet rate, byte rate, TCP flags, fragmentation
- 🚨 **Alert System**: Logs threats to file with confidence scores and detailed packet info
- 📈 **Confidence Scoring**: Rates detected threats on a 0.0-1.0 confidence scale
- 🧵 **Multi-threaded**: Async packet capture and processing

## Project Structure

```
IDS/
├── Main.py                 # Entry point; orchestrates the IDS components
├── PacketCapture.py        # Handles live packet capture from network interface
├── TrafficAnalysis.py      # Extracts features from packets (packet rate, byte rate, etc.)
├── DetectionEngine.py      # ML model inference + 23 rule-based detection methods
├── AlertSystem.py          # Generates and logs security alerts
└── README.md               # This file
```

## Components

### Main.py
The orchestrator that initializes all components and runs the detection loop:
- Prompts for network interface selection
- Starts background packet capture thread
- Processes packets through analysis and detection
- Generates timestamped alerts
- Handles graceful shutdown

### PacketCapture.py
Captures raw network packets:
- Filters for IP layer packets
- Puts packets in a queue for async processing
- Supports stop signal for clean shutdown

### TrafficAnalysis.py
Extracts features from captured packets:
- Detects local IP address automatically
- Calculates per-flow metrics (packet rate, byte rate) over 10-second windows
- Maps destination ports to service names (HTTP, SSH, FTP, etc.)
- Returns structured feature dictionary for detection engine

### DetectionEngine.py
Hybrid detection with ML + rules:
- Loads pre-trained Random Forest model and scaler
- Extracts 10 features per packet for ML inference
- Implements 23 attack detection rules:
  - **Probe Attacks**: IP Sweep, Port Sweep, Nmap, Satan
  - **DoS Attacks**: SYN Flood, Neptune, Smurf, Ping of Death, Teardrop, LAND
  - **Exploit/Malware**: PHF, Buffer Overflow, Loadmodule, Perl, Rootkit
  - **Unauthorized Access**: FTP Write, Guess Password, IMAP, Spy
  - **Data Theft**: Warezclient, Warezmaster
  - **Other**: Back, Multihop
- Returns list of detected threats with type, rule, and confidence

### AlertSystem.py
Generates and logs security alerts:
- Prints real-time console alerts with IP pairs and confidence
- Logs all alerts to `ids_alerts.log` in JSON format
- Escalates high-confidence threats (>0.8) to critical logs

## Installation

### Requirements
- Python 3.7+
- Network interface capable of packet capture (may require admin/root)

### Dependencies
```bash
pip install scapy scikit-learn joblib pandas
```

On Windows, you may also need Npcap for Scapy to work:
https://npcap.com/

### ML Model Files
The DetectionEngine expects pre-trained model files:
- `C:/Users/Webhav/Desktop/pthon/ML Model/rf_model.joblib`
- `C:/Users/Webhav/Desktop/pthon/ML Model/rf_scaler.joblib`

Update the paths in `DetectionEngine.__init__()` if your models are in a different location.

## Usage

### Running the IDS

```bash
python Main.py
```

You'll be prompted to select a network interface:
```
[*] Available interfaces: ['Wi-Fi', 'Ethernet', 'VirtualBox', ...]
[?] Enter interface to sniff on: Wi-Fi
```

Once running, the IDS will display live alerts:
```
[+] IDS running on Wi-Fi (ML threshold=0.5)

2025-12-03 14:35:22 [ALERT] SYN Flood (rule=syn_flood, conf=0.95) 192.168.1.100:54321 → 10.0.0.1:80
2025-12-03 14:35:45 [ALERT] Nmap Scan (rule=nmap, conf=0.90) 192.168.1.50:45000 → 10.0.0.5:22
```

### Adjusting ML Sensitivity

To change the ML detection threshold (default 0.5):
```bash
# In Main.py, modify the ml_threshold parameter
ids = IntrusionDetectionSystem(iface="Wi-Fi", ml_threshold=0.7)  # Higher = fewer false positives
```

## Output Files

- **ids_alerts.log**: All detected threats in JSON format with timestamps
- **ids_system.log**: System-level logs (startup, shutdown, errors)

## Detection Rules

### ML-Based Detection
- Uses Random Forest model trained on network traffic features
- Detects anomalies not matching known attack patterns
- Confidence score: probability from model

### Rule-Based Detection Examples

| Attack Type | Detection Method | Threshold |
|-------------|-----------------|-----------|
| **SYN Flood** | TCP SYN flag + packet rate | >100 pps |
| **Port Sweep** | Unique destination ports per flow | >10 unique ports |
| **Nmap Scan** | Unique destination ports per flow | >20 unique ports |
| **Smurf** | ICMP to broadcast address (.255) | Any detection |
| **Buffer Overflow** | Large packet to service port | >1500 bytes |
| **LAND Attack** | Matching source & destination IP:port pairs | Any detection |
| **Teardrop** | Fragmented packet with high offset | Offset >500 |

## Stopping the IDS

Press `Ctrl+C` to gracefully shutdown:
```
^C
[!] Shutdown requested by user
[+] Stopping packet capture
[+] IDS has stopped
```

## Security Considerations

- Run with appropriate permissions (admin on Windows, root on Linux) for packet capture
- Test in a safe lab environment before production deployment
- ML model paths must be accessible and validated
- Review alert logs regularly for false positives
- Configure firewall rules if needed to avoid alerting on your own traffic

## Future Enhancements

- [ ] Database backend for alert storage
- [ ] Dashboard/visualization of threat trends
- [ ] Automated response actions (blocking IPs, etc.)
- [ ] Support for HTTPS traffic analysis
- [ ] More sophisticated stateful detection
- [ ] Performance optimization for high-traffic networks

## License

This project is provided as-is for educational and authorized security testing purposes.

## Author

Webav-X
