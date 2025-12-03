# Main.py

import threading
import logging
from queue import Empty
from datetime import datetime
from scapy.all import get_if_list, TCP, IP
from PacketCapture import PacketCapturer
from TrafficAnalysis import TrafficAnalyzer
from DetectionEngine import DetectionEngine
from AlertSystem import AlertSystem

class IntrusionDetectionSystem:
    def __init__(self, iface: str = None, ml_threshold: float = 0.5):
        # List interfaces and prompt if needed
        print("[*] Available interfaces:", get_if_list())
        self.interface = iface or input("[?] Enter interface to sniff on: ").strip()
        print(f"[+] Sniffing on interface: {self.interface}")

        # Initialize components
        self.capturer = PacketCapturer()
        self.analyzer = TrafficAnalyzer(iface=self.interface)
        self.engine   = DetectionEngine(threshold=ml_threshold)
        self.alerts   = AlertSystem()
        self._stop    = threading.Event()

    def start(self):
        logging.info(f"Starting IDS on {self.interface}")
        print(f"[+] IDS running on {self.interface} (ML threshold={self.engine.threshold})\n")

        t = threading.Thread(
            target=self.capturer.start_capture,
            args=(self.interface,),
        )
        t.daemon = True
        t.start()

        try:
            while not self._stop.is_set():
                try:
                    pkt = self.capturer.packet_queue.get(timeout=1)
                except Empty:
                    continue

                features = self.analyzer.analyze_packet(pkt)
                if not features:
                    continue

                threats = self.engine.detect(features)
                for th in threats:
                    pkt_info = {
                        "source_ip":       features["source_ip"],
                        "destination_ip":  features["destination_ip"],
                        "source_port":     features["source_port"],
                        "destination_port":features["destination_port"]
                    }
                    # Fire the alert
                    self.alerts.generate_alert(th, pkt_info)
                    # Timestamped console output
                    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    print(f"{ts} [ALERT] {th['type']} (rule={th['rule']}, conf={th['confidence']:.2f}) "
                          f"{pkt_info['source_ip']}:{pkt_info['source_port']} → "
                          f"{pkt_info['destination_ip']}:{pkt_info['destination_port']}")

        except KeyboardInterrupt:
            print("\n[!] Shutdown requested by user")
        finally:
            self.shutdown()

    def shutdown(self):
        print("[+] Stopping packet capture")
        self.capturer.stop()
        self._stop.set()
        logging.info("IDS shutdown complete")
        print("[+] IDS has stopped")

if __name__ == "__main__":
    logging.basicConfig(
        filename="ids_system.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    # Prompt for interface; adjust ml_threshold if you want more sensitivity
    ids = IntrusionDetectionSystem(iface=None, ml_threshold=0.5)
    ids.start()
