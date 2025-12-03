# PacketCapture.py

from scapy.all import sniff, IP
import threading
import queue

class PacketCapturer:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self._stop_event = threading.Event()

    def _packet_handler(self, packet):
        if IP in packet:
            self.packet_queue.put(packet)

    def start_capture(self, interface=None):
        sniff(
            prn=self._packet_handler,
            store=False,
            iface=interface,
            stop_filter=lambda pkt: self._stop_event.is_set()
        )

    def stop(self):
        self._stop_event.set()
