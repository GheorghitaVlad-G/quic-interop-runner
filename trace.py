import datetime
import logging
from enum import Enum
from typing import List, Optional, Tuple

import pyshark

IP4_CLIENT = "193.167.0.100"
IP4_SERVER = "193.167.100.100"
IP6_CLIENT = "fd00:cafe:cafe:0::100"
IP6_SERVER = "fd00:cafe:cafe:100::100"


QUIC_V2 = hex(0x6B3343CF)


class Direction(Enum):
    ALL = 0
    FROM_CLIENT = 1
    FROM_SERVER = 2
    INVALID = 3


class PacketType(Enum):
    INITIAL = 1
    HANDSHAKE = 2
    ZERORTT = 3
    RETRY = 4
    ONERTT = 5
    VERSIONNEGOTIATION = 6
    INVALID = 7


WIRESHARK_PACKET_TYPES = {
    PacketType.INITIAL: "0",
    PacketType.ZERORTT: "1",
    PacketType.HANDSHAKE: "2",
    PacketType.RETRY: "3",
}


WIRESHARK_PACKET_TYPES_V2 = {
    PacketType.INITIAL: "1",
    PacketType.ZERORTT: "2",
    PacketType.HANDSHAKE: "3",
    PacketType.RETRY: "0",
}


def get_direction(p) -> Direction:
    if (hasattr(p, "ip") and p.ip.src == IP4_CLIENT) or (
        hasattr(p, "ipv6") and p.ipv6.src == IP6_CLIENT
    ):
        return Direction.FROM_CLIENT

    if (hasattr(p, "ip") and p.ip.src == IP4_SERVER) or (
        hasattr(p, "ipv6") and p.ipv6.src == IP6_SERVER
    ):
        return Direction.FROM_SERVER

    return Direction.INVALID


def get_packet_type(p) -> PacketType:
    if p.quic.header_form == "0":
        return PacketType.ONERTT
    if p.quic.version == "0x00000000":
        return PacketType.VERSIONNEGOTIATION
    if p.quic.version == QUIC_V2:
        for t, num in WIRESHARK_PACKET_TYPES_V2.items():
            if p.quic.long_packet_type_v2 == num:
                return t
        return PacketType.INVALID
    for t, num in WIRESHARK_PACKET_TYPES.items():
        if p.quic.long_packet_type == num:
            return t
    return PacketType.INVALID


class TraceAnalyzer:
    _filename = ""
    _protocol = "quic"

    def __init__(self, filename: str, keylog_file: Optional[str] = None, protocol: str = "quic"):
        self._filename = filename
        self._keylog_file = keylog_file
        self._protocol = protocol

    def _get_direction_filter(self, d: Direction) -> str:
        proto = "quic" if self._protocol == "quic" else "tcp"
        f = f"({proto} && !icmp) && "
        if d == Direction.FROM_CLIENT:
            return (
                f + "(ip.src==" + IP4_CLIENT + " || ipv6.src==" + IP6_CLIENT + ") && "
            )
        elif d == Direction.FROM_SERVER:
            return (
                f + "(ip.src==" + IP4_SERVER + " || ipv6.src==" + IP6_SERVER + ") && "
            )
        else:
            return f

    def _get_packets(self, f: str) -> List:
        override_prefs = {}
        if self._keylog_file is not None:
            override_prefs["tls.keylog_file"] = self._keylog_file
        cap = pyshark.FileCapture(
            self._filename,
            display_filter=f,
            override_prefs=override_prefs,
            disable_protocol="http3",
            decode_as={"udp.port==443": "quic"},
        )
        packets = []
        try:
            for p in cap:
                # For TCP protocol, check for tcp layer instead of quic
                expected_layer = "tcp" if self._protocol == "tcp" else "quic"
                if expected_layer not in p:
                    logging.debug("Captured packet without %s layer: %r", expected_layer, p)
                    continue
                packets.append(p)
        except Exception as e:
            logging.debug(e)
        cap.close()

        if self._keylog_file is not None and self._protocol == "quic":
            for p in packets:
                if hasattr(p["quic"], "decryption_failed"):
                    logging.info("At least one QUIC packet could not be decrypted")
                    logging.debug(p)
                    break
        return packets

    def get_raw_packets(self, direction: Direction = Direction.ALL) -> List:
        packets = []
        proto = "quic" if self._protocol == "quic" else "tcp"
        for packet in self._get_packets(self._get_direction_filter(direction) + proto):
            packets.append(packet)
        return packets

    def get_1rtt(self, direction: Direction = Direction.ALL) -> List:
        """Get all QUIC packets, one or both directions."""
        packets, _, _ = self.get_1rtt_sniff_times(direction)
        return packets

    def get_1rtt_sniff_times(
        self, direction: Direction = Direction.ALL
    ) -> Tuple[List, datetime.datetime, datetime.datetime]:
        """Get all data packets, one or both directions, and first and last sniff times."""
        packets = []
        first, last = 0, 0
        filter = self._get_direction_filter(direction)
        if self._protocol == "quic":
            filter += "quic.header_form==0"
        else:
            filter += "tcp.len > 0"
        
        # For TCP, use tshark directly for much faster processing
        if self._protocol == "tcp":
            import subprocess
            import datetime
            try:
                # Use tshark to extract just the timestamps we need (much faster than pyshark)
                cmd = [
                    "tshark",
                    "-r", self._filename,
                    "-Y", filter,
                    "-T", "fields",
                    "-e", "frame.time_epoch"
                ]
                
                logging.debug("Running tshark with filter: %s", filter)
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode != 0:
                    logging.error("tshark failed: %s", result.stderr)
                    return packets, first, last
                
                timestamps = []
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            timestamps.append(float(line))
                        except ValueError:
                            continue
                
                if len(timestamps) < 2:
                    logging.info("Not enough TCP packets found")
                    return packets, first, last
                
                # Convert to datetime objects
                first = datetime.datetime.fromtimestamp(timestamps[0])
                last = datetime.datetime.fromtimestamp(timestamps[-1])
                
                logging.debug("Read %d TCP data packets (fast method)", len(timestamps))
                # We don't need the actual packet objects for timing, just return empty list
                return packets, first, last
                
            except subprocess.TimeoutExpired:
                logging.error("tshark timed out")
                return packets, first, last
            except Exception as e:
                logging.error("Error running tshark: %s", e)
                return packets, first, last
        
        # Original QUIC logic
        for packet in self._get_packets(filter):
            for layer in packet.layers:
                if layer.layer_name == self._protocol:
                    if self._protocol == "quic":
                        if (
                            not hasattr(layer, "long_packet_type")
                            and not hasattr(layer, "long_packet_type_v2")
                        ):
                            if first == 0:
                                first = packet.sniff_time
                            last = packet.sniff_time
                            packets.append(layer)
        return packets, first, last

    def get_vnp(self, direction: Direction = Direction.ALL) -> List:
        return self._get_packets(
            self._get_direction_filter(direction) + "quic.version==0"
        )

    def _get_long_header_packets(
        self, packet_type: PacketType, direction: Direction
    ) -> List:
        packets = []
        for packet in self._get_packets(
            self._get_direction_filter(direction)
            + "(quic.long.packet_type || quic.long.packet_type_v2)"
        ):
            for layer in packet.layers:
                if layer.layer_name == "quic" and (
                    (
                        hasattr(layer, "long_packet_type")
                        and layer.long_packet_type
                        == WIRESHARK_PACKET_TYPES[packet_type]
                    )
                    or (
                        hasattr(layer, "long_packet_type_v2")
                        and layer.long_packet_type_v2
                        == WIRESHARK_PACKET_TYPES_V2[packet_type]
                    )
                ):
                    packets.append(layer)
        return packets

    def get_initial(self, direction: Direction = Direction.ALL) -> List:
        """Get all Initial packets."""
        return self._get_long_header_packets(PacketType.INITIAL, direction)

    def get_retry(self, direction: Direction = Direction.ALL) -> List:
        """Get all Retry packets."""
        return self._get_long_header_packets(PacketType.RETRY, direction)

    def get_handshake(self, direction: Direction = Direction.ALL) -> List:
        """Get all Handshake packets."""
        return self._get_long_header_packets(PacketType.HANDSHAKE, direction)

    def get_0rtt(self) -> List:
        """Get all 0-RTT packets."""
        return self._get_long_header_packets(PacketType.ZERORTT, Direction.FROM_CLIENT)
