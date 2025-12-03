# AlertSystem.py

import logging
import json
from datetime import datetime

class AlertSystem:
    def __init__(self, log_file="ids_alerts.log"):
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            fh = logging.FileHandler(log_file)
            fmt = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            fh.setFormatter(fmt)
            self.logger.addHandler(fh)

    def generate_alert(self, threat, packet_info):
        alert = {
            "timestamp": datetime.now().isoformat(),
            "threat_type": threat["type"],
            "rule": threat.get("rule"),
            "source_ip": packet_info.get("source_ip", "Unknown"),
            "destination_ip": packet_info.get("destination_ip", "Unknown"),
            "confidence": threat.get("confidence", 0.0)
        }

        print(f"[ALERT] {alert['threat_type']} from {alert['source_ip']} → {alert['destination_ip']} "
              f"[Confidence: {alert['confidence']:.2f}]")
        payload = json.dumps(alert)
        self.logger.warning(payload)
        if alert["confidence"] > 0.8:
            self.logger.critical(f"High confidence threat: {payload}")
