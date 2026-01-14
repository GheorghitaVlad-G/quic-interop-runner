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

        decode_as = {}
        disable_protocol = None
        if self._protocol == "quic":
            decode_as = {"udp.port==443": "quic"}
            disable_protocol = "http3"

        cap = pyshark.FileCapture(
            self._filename,
            display_filter=f,
            override_prefs=override_prefs,
            disable_protocol=disable_protocol,
            decode_as=decode_as if decode_as else None,
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
    
    def get_tcp_handshake_complete_time(self) -> float:
        """
        For TCP: Get time from first SYN to final ACK of 3-way handshake.
        Returns time in milliseconds, or None if handshake not found.
        """
        if self._protocol != "tcp":
            return None
        
        try:
            # Get SYN packet (client to server)
            syn_packets = self._get_packets(
                self._get_direction_filter(Direction.FROM_CLIENT) + 
                "tcp.flags.syn==1 && tcp.flags.ack==0"
            )
            
            # Get SYN-ACK packet (server to client)
            synack_packets = self._get_packets(
                self._get_direction_filter(Direction.FROM_SERVER) + 
                "tcp.flags.syn==1 && tcp.flags.ack==1"
            )
            
            # Get final ACK (client to server, after SYN-ACK)
            ack_packets = self._get_packets(
                self._get_direction_filter(Direction.FROM_CLIENT) + 
                "tcp.flags.ack==1 && tcp.flags.syn==0 && tcp.len==0"
            )
            
            if not syn_packets or not synack_packets:
                logging.debug("Missing SYN or SYN-ACK packets")
                return None
            
            syn_time = float(syn_packets[0].sniff_timestamp)
            synack_time = float(synack_packets[0].sniff_timestamp)
            
            # Find the first ACK after SYN-ACK
            final_ack_time = None
            for p in ack_packets:
                ack_time = float(p.sniff_timestamp)
                if ack_time > synack_time:
                    final_ack_time = ack_time
                    break
            
            if final_ack_time is None:
                # Fallback: just use SYN to SYN-ACK time
                logging.debug("No final ACK found, using SYN to SYN-ACK")
                return (synack_time - syn_time) * 1000
            
            return (final_ack_time - syn_time) * 1000
            
        except Exception as e:
            logging.debug("Error calculating TCP handshake time: %s", e)
            return None

    def get_retransmissions(self, direction: Direction = Direction.ALL) -> List:
        """
        Get all retransmitted packets.
        For QUIC: uses Wireshark's retransmission detection
        For TCP: uses tcp.analysis.retransmission
        """
        packets = []
        
        if self._protocol == "quic":
            import subprocess
            
            direction_filter = self._get_direction_filter(direction)
            
            # Build tshark filter
            if direction_filter:
                base_filter = f"{direction_filter}quic.stream.stream_id"
            else:
                base_filter = "quic.stream.stream_id"
            
            # Try to get stream data to calculate lengths
            cmd = [
                'tshark',
                '-r', self._filename,
                '-Y', base_filter,
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'quic.stream.stream_id',
                '-e', 'quic.stream.offset',
                '-e', 'quic.stream_data',
                '-E', 'separator=|',
                '-E', 'occurrence=a'
            ]
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
                lines = [l for l in result.stdout.strip().split('\n') if l.strip()]
                
                logging.info(f"Found {len(lines)} lines with QUIC stream data")
                
                if not lines:
                    logging.warning("No QUIC stream data found")
                    return packets
                
                # Track seen data ranges per stream
                seen_ranges = {}  # stream_id -> list of (offset, offset+length)
                retrans_frame_numbers = set()
                processed_count = 0
                skipped_no_data = 0
                
                for line in lines:
                    parts = line.split('|')
                    if len(parts) < 4:
                        continue
                    
                    try:
                        frame_num = int(parts[0])
                        
                        # Handle multiple streams per packet (comma-separated)
                        stream_ids = [s.strip() for s in parts[1].split(',') if s.strip()]
                        offsets = [s.strip() for s in parts[2].split(',') if s.strip()]
                        stream_datas = [s.strip() for s in parts[3].split(',') if s.strip()]
                        
                        if not stream_ids:
                            continue
                        
                        # Process each stream frame in this packet
                        for idx, stream_id_str in enumerate(stream_ids):
                            stream_id = int(stream_id_str)
                            
                            # Get offset (may be empty for offset 0)
                            if idx < len(offsets) and offsets[idx]:
                                offset = int(offsets[idx])
                            else:
                                offset = 0
                            
                            # Calculate length from hex stream data
                            if idx < len(stream_datas) and stream_datas[idx]:
                                # Stream data is in hex format like "6162636465..."
                                # Each byte is 2 hex chars, so length = len(hex_string) / 2
                                hex_data = stream_datas[idx].replace(':', '')
                                length = len(hex_data) // 2
                            else:
                                skipped_no_data += 1
                                continue
                            
                            if length == 0:
                                continue
                            
                            processed_count += 1
                            
                            # Initialize stream tracking
                            if stream_id not in seen_ranges:
                                seen_ranges[stream_id] = []
                            
                            start = offset
                            end = offset + length
                            
                            # Check for overlap with previously seen ranges
                            is_retransmission = False
                            for seen_start, seen_end in seen_ranges[stream_id]:
                                if start < seen_end and end > seen_start:
                                    is_retransmission = True
                                    retrans_frame_numbers.add(frame_num)
                                    if len(retrans_frame_numbers) <= 5:
                                        logging.info(f"Retransmission: frame={frame_num}, stream={stream_id}, "
                                                f"offset=[{offset}, {offset+length}), overlaps [{seen_start}, {seen_end})")
                                    break
                            
                            if not is_retransmission:
                                seen_ranges[stream_id].append((start, end))
                    
                    except (ValueError, IndexError) as e:
                        logging.debug(f"Error parsing line '{line[:100]}': {e}")
                        continue
                
                logging.info(f"Processed {processed_count} stream data frames, skipped {skipped_no_data} without data")
                logging.info(f"Found {len(retrans_frame_numbers)} frames with retransmissions across {len(seen_ranges)} streams")
                
                # Fetch actual packet objects for retransmission frames
                if retrans_frame_numbers:
                    frame_nums = sorted(list(retrans_frame_numbers))
                    chunk_size = 500
                    for i in range(0, len(frame_nums), chunk_size):
                        chunk = frame_nums[i:i+chunk_size]
                        frame_filter = " or ".join([f"frame.number == {num}" for num in chunk])
                        chunk_packets = self._get_packets(frame_filter)
                        packets.extend(chunk_packets)
                    
                    logging.info(f"Retrieved {len(packets)} retransmission packet objects")
                
            except subprocess.CalledProcessError as e:
                logging.error(f"tshark command failed: {e.stderr}")
            except Exception as e:
                logging.error(f"Error processing QUIC retransmissions: {e}")
        else:
            tcp_filter = self._get_direction_filter(direction)
            if tcp_filter:
                full_filter = f"{tcp_filter}tcp.analysis.retransmission"
            else:
                full_filter = "tcp.analysis.retransmission"
            
            packets = self._get_packets(full_filter)
        
        return packets

    def get_packet_arrival_times(self, direction: Direction = Direction.ALL) -> List[float]:
        """
        Get timestamps of all packets in order of arrival.
        Used for jitter and reordering analysis.
        """
        packets = self.get_raw_packets(direction)
        return [float(p.sniff_timestamp) for p in packets]

    def get_packet_numbers(self, direction: Direction = Direction.ALL) -> List[int]:
        """
        Get packet numbers (for QUIC) or sequence numbers (for TCP).
        Used for reordering detection.
        """
        packets = self.get_raw_packets(direction)
        numbers = []
        
        for p in packets:
            if self._protocol == "quic":
                if hasattr(p.quic, "packet_number"):
                    numbers.append(int(p.quic.packet_number))
            else:  # TCP
                if hasattr(p.tcp, "seq"):
                    numbers.append(int(p.tcp.seq))
        
        return numbers

    def get_stream_data_packets(self, direction: Direction = Direction.ALL) -> List:
        """
        Get packets containing application data.
        For QUIC: STREAM frames with data
        For TCP: segments with payload
        """
        packets = []
        
        if self._protocol == "quic":
            # Use the display filter to get QUIC packets with stream data
            direction_filter = self._get_direction_filter(direction)
            if direction_filter:
                filter_str = f"{direction_filter}quic.stream_data"
            else:
                filter_str = "quic.stream_data"
            
            packets = self._get_packets(filter_str)
        else:  # TCP
            filter_str = self._get_direction_filter(direction) + "tcp.len > 0"
            packets = self._get_packets(filter_str)
        
        return packets
