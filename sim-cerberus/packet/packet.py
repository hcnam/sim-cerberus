#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class Packet:
    def __init__(self, src_ip: bytes, src_port: bytes, dst_ip: bytes, dst_port: bytes, protocol: str, packet_size: int, tick: int, attack_type: int):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        if protocol.startswith("ICMP"):
            self.protocol_byte = int_to_bytes(1, 1)
        elif protocol.startswith("TCP"):
            self.protocol_byte = int_to_bytes(6, 1)
        elif protocol.startswith("UDP"):
            self.protocol_byte = int_to_bytes(17, 1)
        else:
            raise ValueError(f"Invalid protocol: {protocol}")
        self.packet_size = packet_size
        self.tick = tick    # subtick
        self.attack_type = attack_type
        # p.count is defined at attack_generator.py, for debugging seq

    def __str__(self):
        return f"Source {bytes_to_ip(self.src_ip)}: {int.from_bytes(self.src_port, byteorder='big')}\t" + \
               f"Destination {bytes_to_ip(self.dst_ip)}: {int.from_bytes(self.dst_port, byteorder='big')}\t" + \
               f"Protocol {self.protocol}\t" + \
               f"Size {self.packet_size}\t" + \
               f"Subtick {self.tick}"

    def __repr__(self):
        return f"\n{self.__str__()}"

    def get(self, key: str):
        if key == "src_ip":
            return self.src_ip
        elif key == "src_port":
            return self.src_port
        elif key == "dst_ip":
            return self.dst_ip
        elif key == "dst_port":
            return self.dst_port
        elif key == "protocol":
            return self.protocol
        elif key == "protocol_byte":
            return self.protocol_byte
        elif key == "packet_size":
            return self.packet_size
        elif key == "tick":
            return self.tick
        raise ValueError(f"Wrong key: {key}")

def ip_to_bytes(ip: str) -> bytes:
    l = ip.split(".")
    l = [int(x) for x in l]
    return bytes(l)

def int_to_bytes(n: int, byte_length: int) -> bytes:
    return n.to_bytes(byte_length, byteorder='big', signed=False)

def bytes_to_ip(b: bytes) -> str:
    return ".".join([str(x) for x in b])
