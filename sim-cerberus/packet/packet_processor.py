#!/usr/bin/env python3
# -*- coding: utf-8 -*-

try:
    from . import packet as pkt
except ImportError:
    import packet as pkt
from scapy.all import *
import os

class Processor:
    def __init__(self, filename: str):
        if not os.path.isfile(filename):
            raise ValueError(f"{filename} does not exist")
        self.reader = PcapReader(filename)

    def process_pcap(self, max_length: float, tick: int) -> list[pkt.Packet]:
        length = 0
        packets = []

        FIN = 0x01
        SYN = 0x02
        RST = 0x04
        ACK = 0x10

        for p in self.reader:
            if IP in p:
                src_ip = pkt.ip_to_bytes(p[IP].src)
                dst_ip = pkt.ip_to_bytes(p[IP].dst)
                if TCP in p:
                    src_port = p[TCP].sport
                    dst_port = p[TCP].dport
                    tcp_flags = p[TCP].flags
                    if tcp_flags & SYN and not tcp_flags & ACK:
                        protocol = "TCP_SYN"
                    elif tcp_flags & SYN and tcp_flags & ACK:
                        protocol = "TCP_SNACK"
                    elif tcp_flags & ACK:
                        protocol = "TCP_ACK"
                    elif tcp_flags & FIN:
                        protocol = "TCP_FIN"
                    elif tcp_flags & RST:
                        protocol = "TCP_RST"
                    else:
                        protocol = "TCP"
                elif UDP in p:
                    src_port = p[UDP].sport
                    dst_port = p[UDP].dport
                    protocol = "UDP"
                elif ICMP in p:
                    src_port = 0
                    dst_port = 0
                    protocol = "ICMP"
                else:
                    src_port = 0
                    dst_port = 0
                    protocol = "Unknown"
                src_port = pkt.int_to_bytes(src_port, 2)
                dst_port = pkt.int_to_bytes(dst_port, 2)
                packet_size = p.len
                # timestamp = p.time

                packet = pkt.Packet(src_ip, src_port, dst_ip, dst_port, protocol, packet_size, tick, -1)
                packets.append(packet)

                length += packet_size
                if length >= max_length:
                    break

        return packets

if __name__ == '__main__':
    processor = Processor(f"{os.path.dirname(os.path.realpath(__file__))}/../202404251400.pcap")
    for tick in range(2):
        print(f"====================== Tick {tick} ======================")
        packets = processor.process_pcap(2000, tick)  # Read 2000B of packets (or little more) for two ticks
        for packet in packets:
            print(f"Source IP: {packet.src_ip}")
            print(f"Source Port: {packet.src_port}")
            print(f"Destination IP: {packet.dst_ip}")
            print(f"Destination Port: {packet.dst_port}")
            print(f"Protocol: {packet.protocol}")
            print(f"Packet Size: {packet.packet_size}")
            print(f"Tick: {packet.tick}")
            print("==================================================")
        print()
        print()

# if __name__ == '__main__':
#     processor = Processor(f"{os.path.dirname(os.path.realpath(__file__))}/../202404251400.pcap")
#     packets = processor.process_pcap(16 * 1000*1000*1000/8, 0)  # Read 16s * 1Gbps of packets (or little more)
#     src_dst_ip_dict = set()
#     for packet in packets:
#         src_dst_ip_dict.add((packet.src_ip, packet.dst_ip))
#     print(f"Number of distinct 2-tuple(src/dst ip pair)s: {len(src_dst_ip_dict)}")
