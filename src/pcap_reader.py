"""Bounded PCAP/PCAPNG parsing without dissecting packet payloads."""

import ipaddress
import sys
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO

from scapy.utils import RawPcapReader

from features import extract_features
from flows import Flow, FlowTable, flow_key

MAX_CAPTURE_PACKETS = 100_000
MAX_CAPTURE_FLOWS = 25_000


class CaptureError(ValueError):
    """A capture is malformed, unsupported, or exceeds processing limits."""


@dataclass
class FlowRecord:
    flow_id: str
    flow: Flow
    features: dict


@dataclass
class CaptureData:
    flows: list[FlowRecord]
    packets_read: int
    transport_packets: int
    bytes_read: int
    skipped_flows: int
    truncated: bool
    start_time: float | None
    end_time: float | None


def packet_network_fields(frame: bytes, linktype: int | None):
    """Read only link, IP and TCP/UDP headers at known offsets."""
    if linktype is None:
        return None
    linktype = int(linktype) & 0xFFFF
    if linktype == 1:  # Ethernet II
        if len(frame) < 14:
            return None
        ether_type = int.from_bytes(frame[12:14], "big")
        offset = 14
        vlan_count = 0
        while ether_type in (0x8100, 0x88A8, 0x9100):
            if len(frame) < offset + 4 or vlan_count == 8:
                return None
            ether_type = int.from_bytes(frame[offset + 2 : offset + 4], "big")
            offset += 4
            vlan_count += 1
    elif linktype == 113:  # Linux cooked capture v1
        if len(frame) < 16:
            return None
        ether_type, offset = int.from_bytes(frame[14:16], "big"), 16
    elif linktype == 276:  # Linux cooked capture v2
        if len(frame) < 20:
            return None
        ether_type, offset = int.from_bytes(frame[:2], "big"), 20
    elif linktype in (101, 12):  # Raw IP, link header omitted
        if not frame:
            return None
        version = frame[0] >> 4
        ether_type = 0x0800 if version == 4 else 0x86DD if version == 6 else 0
        offset = 0
    elif linktype == 228:
        ether_type, offset = 0x0800, 0
    elif linktype == 229:
        ether_type, offset = 0x86DD, 0
    elif linktype in (0, 108):  # BSD loopback
        if len(frame) < 4:
            return None
        family = int.from_bytes(frame[:4], sys.byteorder if linktype == 0 else "big")
        ether_type = 0x0800 if family == 2 else 0x86DD if family in {10, 24, 28, 30} else 0
        offset = 4
    else:
        return None

    if ether_type == 0x0800:  # IPv4
        if len(frame) < offset + 20 or frame[offset] >> 4 != 4:
            return None
        header_size = (frame[offset] & 0x0F) * 4
        if header_size < 20 or len(frame) < offset + header_size:
            return None
        fragment = int.from_bytes(frame[offset + 6 : offset + 8], "big")
        if fragment & 0x1FFF:  # Non-initial fragments lack transport ports.
            return None
        protocol_number = frame[offset + 9]
        source = str(ipaddress.ip_address(frame[offset + 12 : offset + 16]))
        destination = str(ipaddress.ip_address(frame[offset + 16 : offset + 20]))
        transport_offset = offset + header_size
    elif ether_type == 0x86DD:  # IPv6 plus common extension headers
        if len(frame) < offset + 40 or frame[offset] >> 4 != 6:
            return None
        source = str(ipaddress.ip_address(frame[offset + 8 : offset + 24]))
        destination = str(ipaddress.ip_address(frame[offset + 24 : offset + 40]))
        protocol_number = frame[offset + 6]
        transport_offset = offset + 40
        for _ in range(8):
            if protocol_number in (0, 43, 60):
                if len(frame) < transport_offset + 2:
                    return None
                next_header = frame[transport_offset]
                extension_size = (frame[transport_offset + 1] + 1) * 8
            elif protocol_number == 44:
                if len(frame) < transport_offset + 8:
                    return None
                fragment = int.from_bytes(
                    frame[transport_offset + 2 : transport_offset + 4], "big"
                )
                if (fragment >> 3) & 0x1FFF:
                    return None
                next_header, extension_size = frame[transport_offset], 8
            elif protocol_number == 51:
                if len(frame) < transport_offset + 2:
                    return None
                next_header = frame[transport_offset]
                extension_size = (frame[transport_offset + 1] + 2) * 4
            else:
                break
            if extension_size <= 0 or len(frame) < transport_offset + extension_size:
                return None
            protocol_number = next_header
            transport_offset += extension_size
        else:
            return None
    else:
        return None

    protocol = {6: "TCP", 17: "UDP"}.get(protocol_number)
    if protocol is None or len(frame) < transport_offset + 4:
        return None
    source_port = int.from_bytes(frame[transport_offset : transport_offset + 2], "big")
    destination_port = int.from_bytes(frame[transport_offset + 2 : transport_offset + 4], "big")
    return source, destination, source_port, destination_port, protocol


def _packet_timestamp(metadata, reader):
    seconds = getattr(metadata, "sec", None)
    subseconds = getattr(metadata, "usec", None)
    if seconds is not None and subseconds is not None:
        divisor = 1_000_000_000 if getattr(reader, "nano", False) else 1_000_000
        return float(seconds) + float(subseconds) / divisor
    high = getattr(metadata, "tshigh", None)
    low = getattr(metadata, "tslow", None)
    resolution = getattr(metadata, "tsresol", None)
    if high is None or low is None or not resolution:
        raise CaptureError("This capture has packets without timestamps; timing is required.")
    return ((int(high) << 32) | int(low)) / float(resolution)


def read_capture(capture_bytes: bytes, *, max_packets=MAX_CAPTURE_PACKETS,
                 max_flows=MAX_CAPTURE_FLOWS) -> CaptureData:
    """Build payload-free flow records from a bounded raw capture byte string."""
    if not capture_bytes:
        raise CaptureError("The capture is empty.")
    table = FlowTable()
    packets_read = transport_packets = 0
    skipped_keys = set()
    first_timestamp = last_timestamp = None
    truncated = False
    reader = None
    try:
        reader = RawPcapReader(BytesIO(capture_bytes))
        for frame, metadata in reader:
            if packets_read >= max_packets:
                truncated = True
                break
            packets_read += 1
            expected_frame_length = getattr(metadata, "caplen", None)
            if expected_frame_length is not None and len(frame) != int(expected_frame_length):
                raise CaptureError("This capture ends in a truncated packet record.")
            linktype = getattr(metadata, "linktype", getattr(reader, "linktype", None))
            fields = packet_network_fields(frame, linktype)
            if fields is None:
                continue
            timestamp = _packet_timestamp(metadata, reader)
            src_ip, dst_ip, src_port, dst_port, protocol = fields
            transport_packets += 1
            first_timestamp = timestamp if first_timestamp is None else min(first_timestamp, timestamp)
            last_timestamp = timestamp if last_timestamp is None else max(last_timestamp, timestamp)
            key = flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
            if key not in table.flows and len(table.flows) >= max_flows:
                skipped_keys.add(key)
                continue
            flow = table.get_or_create(src_ip, dst_ip, src_port, dst_port, protocol)
            direction = table.direction_for(flow, src_ip, src_port)
            flow.add_packet(size=len(frame), direction=direction, ts=timestamp)
    except CaptureError:
        raise
    except Exception as exc:
        raise CaptureError("Could not parse this PCAP/PCAPNG capture.") from exc
    finally:
        if reader is not None:
            reader.close()
    if packets_read == 0:
        raise CaptureError("This capture contains no readable packets.")

    all_flows = table.all_flows()
    _annotate_concurrency(all_flows)
    records = []
    for flow in all_flows:
        features = extract_features(
            flow.packets, proto=flow.proto, server_port=flow.server_port,
            max_concurrent_flows=flow.max_concurrent_flows,
        )
        if features is None:
            continue
        opaque_id = sha256(repr(flow.key).encode("utf-8")).hexdigest()[:12]
        records.append(FlowRecord(opaque_id, flow, features))
    return CaptureData(
        flows=records,
        packets_read=packets_read,
        transport_packets=transport_packets,
        bytes_read=len(capture_bytes),
        skipped_flows=len(skipped_keys),
        truncated=truncated,
        start_time=first_timestamp,
        end_time=last_timestamp,
    )


def _annotate_concurrency(flows):
    """Calculate peak overlapping flows per source without rescanning all flows per packet."""
    by_source = {}
    for flow in flows:
        by_source.setdefault(flow.client_ip, []).append(flow)
    for source_flows in by_source.values():
        event_counts = {}
        intervals = []
        for flow in source_flows:
            times = [packet.timestamp for packet in flow.packets]
            if times:
                start, end = min(times), max(times)
                event_counts.setdefault(start, [0, 0])[0] += 1
                event_counts.setdefault(end, [0, 0])[1] += 1
                intervals.append((flow, start, end))
        event_times = sorted(event_counts)
        concurrent = 0
        peaks = []
        for timestamp in event_times:
            starts, ends = event_counts[timestamp]
            concurrent += starts
            peak = concurrent
            concurrent -= ends
            peaks.append(max(peak, concurrent))

        # Range-maximum queries assign each flow its own peak concurrency in O(log n).
        size = 1 << (len(peaks) - 1).bit_length()
        tree = [0] * (2 * size)
        tree[size:size + len(peaks)] = peaks
        for node in range(size - 1, 0, -1):
            tree[node] = max(tree[2 * node], tree[2 * node + 1])

        def range_peak(left, right, _size=size, _tree=tree):
            left += _size
            right += _size
            maximum = 1
            while left <= right:
                if left & 1:
                    maximum = max(maximum, _tree[left])
                    left += 1
                if not right & 1:
                    maximum = max(maximum, _tree[right])
                    right -= 1
                left //= 2
                right //= 2
            return maximum

        for flow, start, end in intervals:
            left = bisect_left(event_times, start)
            right = bisect_right(event_times, end) - 1
            flow.max_concurrent_flows = range_peak(left, right)
