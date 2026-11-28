
import importlib.util
from pathlib import Path
import threading


def save_detected_event(event):
    """Save a detected event using the existing event logger."""

    logger_path = Path(__file__).with_name("event_logger.py")

    spec = importlib.util.spec_from_file_location(
        "event_logger",
        logger_path
    )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module.save_security_event(event)


"""
SENTINAL - Detection Engine

Initial implementation:
1. ARP spoofing detection using IP-to-MAC mapping conflicts.

A security event is generated when an IP address previously
observed with one MAC address is advertised with another.
"""


class DetectionEngine:

    def __init__(self):
        # Stores the first observed MAC for each IP address.
        self.arp_table = {}

        # Prevents repeated alerts for the same conflict.
        self.reported_conflicts = set()

        self.lock = threading.Lock()

    def detect_arp_spoofing(self, packet_event):
        """
        Detect conflicting ARP IP-to-MAC advertisements.

        Returns:
            dict: Security event if a conflict is detected.
            None: If no conflict is detected.
        """

        arp_data = packet_event.get("arp")

        if not arp_data:
            return None

        source_ip = arp_data.get("source_ip")
        source_mac = arp_data.get("source_mac")
        operation = arp_data.get("operation")

        if not source_ip or not source_mac:
            return None

        # Consider ARP requests and replies.
        if operation not in (1, 2):
            return None

        with self.lock:

            known_mac = self.arp_table.get(source_ip)

            # First observation: learn the IP-MAC association.
            if known_mac is None:
                self.arp_table[source_ip] = source_mac
                return None

            # No conflict: the observed mapping is unchanged.
            if known_mac.lower() == source_mac.lower():
                return None

            # Conflicting MAC advertisement detected.
            conflict_key = (
                source_ip,
                known_mac.lower(),
                source_mac.lower()
            )

            # Avoid duplicate alerts for the same conflict.
            if conflict_key in self.reported_conflicts:
                return None

            self.reported_conflicts.add(conflict_key)

            return {
                "event_type": "ARP_SPOOFING_SUSPECTED",
                "source_ip": source_ip,
                "destination_ip": None,
                "protocol": "ARP",
                "threat_score": 85,
                "severity": "HIGH",
                "detection_method": "ARP_MAPPING_CONFLICT",
                "description": (
                    f"Conflicting MAC advertisement detected for "
                    f"IP {source_ip}. Previously observed MAC: "
                    f"{known_mac}; newly observed MAC: {source_mac}."
                ),
                "response_action": "NONE",
                "response_status": "NOT_APPLICABLE"
            }

    def detect_packet(self, packet_event):
        """
        Main detection entry point.

        Returns a security event or None.
        """

        if not packet_event:
            return None

        return self.detect_arp_spoofing(packet_event)

    def process_packet(self, packet_event):
        """Detect suspicious activity and save generated events."""

        security_event = self.detect_packet(packet_event)

        if security_event is None:
            return None

        event_id = save_detected_event(security_event)

        security_event["database_id"] = event_id

        return security_event


# Compatibility function for simple module-level usage.
_default_engine = DetectionEngine()


def detect_packet(packet_event):
    return _default_engine.detect_packet(packet_event)
