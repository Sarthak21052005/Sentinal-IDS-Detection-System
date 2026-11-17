
import argparse
import json
import logging

from scapy.all import sniff, get_if_list

from .packet_processor import process_packet


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("SENTINAL.PacketCapture")


class PacketCapture:
    def __init__(self, interface="enp0s8"):
        self.interface = interface
        self.packet_count = 0

    def process_captured_packet(self, packet):
        """Process and display a captured packet."""

        event = process_packet(packet)

        if event is None:
            return

        self.packet_count += 1

        logger.info(
            "Packet #%s | %s | %s -> %s",
            self.packet_count,
            event["protocol"],
            event["src_ip"],
            event["dst_ip"],
        )

        print(json.dumps(event, indent=2))

    def start_capture(self, count=0):
        """
        Start live packet capture.

        count=0 means capture continuously until interrupted.
        """

        available_interfaces = get_if_list()

        if self.interface not in available_interfaces:
            raise ValueError(
                f"Interface '{self.interface}' not found. "
                f"Available interfaces: {available_interfaces}"
            )

        logger.info(
            "Starting SENTINAL packet capture on %s",
            self.interface
        )

        logger.info(
            "Capture limit: %s",
            count if count > 0 else "Unlimited"
        )

        try:
            sniff(
                iface=self.interface,
                prn=self.process_captured_packet,
                store=False,
                count=count
            )

        except KeyboardInterrupt:
            logger.info("Packet capture stopped by user.")

        except PermissionError:
            logger.error(
                "Permission denied. Packet capture needs "
                "appropriate network capture privileges."
            )
            raise

        finally:
            logger.info(
                "Capture stopped. Total packets processed: %s",
                self.packet_count
            )


def main():
    parser = argparse.ArgumentParser(
        description="SENTINAL live packet capture"
    )

    parser.add_argument(
        "--interface",
        default="enp0s8",
        help="Network interface to monitor"
    )

    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited)"
    )

    args = parser.parse_args()

    if args.count < 0:
        parser.error("--count cannot be negative")

    capture = PacketCapture(interface=args.interface)
    capture.start_capture(count=args.count)


if __name__ == "__main__":
    main()
