import argparse
import time
import binascii
import string
import signal
import sys
from collections import Counter
from scapy.all import sniff, rdpcap, wrpcap, IP, IPv6, TCP, UDP, Raw

# Global stats
packet_counter = Counter()
running = True

def signal_handler(sig, frame):
    global running
    print("\n[!] Interrupt received, stopping capture...")
    running = False

def printable_preview(raw_bytes: bytes, max_len: int = 200) -> str:
    """Return a printable, truncated preview of raw bytes (non-printable replaced by '.')."""
    if not raw_bytes:
        return ""
    preview = raw_bytes[:max_len]
    printable = []
    for b in preview:
        ch = chr(b)
        printable.append(ch if ch in string.printable and ch not in '\r\n\t' else '.')
    s = "".join(printable)
    if len(raw_bytes) > max_len:
        s += "..."
    return s

def summarize_packet(pkt, verbosity=1) -> str:
    """Create a human summary for a packet."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(pkt.time)) if hasattr(pkt, "time") else ""

    src = dst = proto = ttl = pkt_len = "N/A"

    if IP in pkt:
        ip_layer = pkt[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.proto
        ttl = ip_layer.ttl
        pkt_len = ip_layer.len if hasattr(ip_layer, "len") else len(pkt)
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.nh
        ttl = ip_layer.hlim
        pkt_len = len(pkt)
    else:
        src = getattr(pkt, "src", "N/A")
        dst = getattr(pkt, "dst", "N/A")
        ttl = "N/A"
        pkt_len = len(pkt)

    l4_info = ""
    protocol_name = "Unknown"

    if TCP in pkt:
        tcp = pkt[TCP]
        sport = tcp.sport
        dport = tcp.dport
        flags = tcp.flags
        l4_info = f"TCP {sport}->{dport} flags={flags}"
        protocol_name = "TCP"
    elif UDP in pkt:
        udp = pkt[UDP]
        sport = udp.sport
        dport = udp.dport
        l4_info = f"UDP {sport}->{dport}"
        protocol_name = "UDP"
    else:
        last_layer = pkt.lastlayer()
        protocol_name = last_layer.name if last_layer else "Unknown"
        l4_info = protocol_name

    payload_preview = ""
    if Raw in pkt:
        raw = bytes(pkt[Raw].load)
        payload_preview = printable_preview(raw, max_len=120)
        if payload_preview:
            payload_preview = f' payload="{payload_preview}"'

    packet_counter.update([protocol_name])

    summary = f"{ts} {src} -> {dst} | {l4_info} len={pkt_len} ttl={ttl}{payload_preview}"

    if verbosity > 1:
        summary = f"[VERBOSE] {summary}"

    return summary

class Sniffer:
    def __init__(self, iface=None, bpf=None, pcap_out=None, max_count=0, read_pcap=None, verbosity=1):
        self.iface = iface
        self.bpf = bpf
        self.pcap_out = pcap_out
        self.max_count = max_count  # 0 means unlimited
        self.read_pcap = read_pcap
        self.captured = []
        self.verbosity = verbosity

    def process_packet(self, pkt):
        try:
            summary = summarize_packet(pkt, self.verbosity)
            print(summary)
        except Exception as e:
            print(f"[!] Error summarizing packet: {e}")

        if self.pcap_out is not None:
            self.captured.append(pkt)

    def run_live(self):
        print("Starting live capture.")
        print(" Interface:", self.iface or "default")
        print(" BPF filter:", self.bpf or "none")
        print(" Max packets:", "unlimited" if self.max_count == 0 else self.max_count)
        print(" Press Ctrl+C to stop.")

        global running
        sniff_kwargs = {
            "iface": self.iface,
            "filter": self.bpf,
            "prn": self.process_packet,
            "store": False
        }
        if self.max_count > 0:
            sniff_kwargs["count"] = self.max_count

        signal.signal(signal.SIGINT, signal_handler)

        while running:
            sniff(**sniff_kwargs)
            if self.max_count > 0:
                break

        if self.pcap_out and self.captured:
            print(f"Saving {len(self.captured)} packets to {self.pcap_out}")
            wrpcap(self.pcap_out, self.captured)

        self.print_stats()

    def run_from_pcap(self):
        print(f"Reading packets from pcap: {self.read_pcap}")
        pkts = rdpcap(self.read_pcap)
        for pkt in pkts:
            self.process_packet(pkt)

        if self.pcap_out:
            print(f"Saving {len(pkts)} packets to {self.pcap_out}")
            wrpcap(self.pcap_out, pkts)

        self.print_stats()

    def print_stats(self):
        total = sum(packet_counter.values())
        print(f"\nCapture summary: {total} packets")
        for proto, count in packet_counter.items():
            print(f"  {proto}: {count} packets")

def parse_args():
    parser = argparse.ArgumentParser(description="Educational Packet Sniffer (read pcap or capture live).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--interface", "-i", help="Network interface to sniff (requires privileges).")
    group.add_argument("--pcap", "-r", help="Read packets from a pcap file (safe, recommended for labs).")

    parser.add_argument("--filter", "-f", help="BPF filter to limit capture (example: 'tcp and port 80')", default=None)
    parser.add_argument("--out", "-w", help="Write captured packets to this pcap file (optional).", default=None)
    parser.add_argument("--count", "-c", type=int, help="Number of packets to capture (0 = unlimited).", default=0)
    parser.add_argument("--verbose", "-v", action="count", default=1, help="Increase output verbosity (use -v or -vv).")
    return parser.parse_args()

def main():
    args = parse_args()

    print("WARNING: Use this tool only on networks you own or where you have permission.")

    sniffer = None
    if args.interface:
        sniffer = Sniffer(
            iface=args.interface,
            bpf=args.filter,
            pcap_out=args.out,
            max_count=args.count,
            verbosity=args.verbose
        )
        sniffer.run_live()
    else:
        sniffer = Sniffer(
            read_pcap=args.pcap,
            pcap_out=args.out,
            verbosity=args.verbose
        )
        sniffer.run_from_pcap()

if __name__ == "__main__":
    main()
