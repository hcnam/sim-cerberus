#!/usr/bin/env python3
# -*- coding: utf-8 -*-

try:
    from . import packet as pkt
except ImportError:
    import packet as pkt
from typing import List, Dict
import unittest
import math
from random import randint, choice, choices, random
import os
import yaml

largest_psize, smallest_psize = 1518, 64

class AttackGenerator:
    def __init__(self, benign_unique_flowkey: int, attack_unique_ip: int, atk_profile_yaml: str, benign_volume, attack_volume, refresh_cycle_per_attack: dict[str, int], tick_divisor: int, attack_tick_to_subtick: int, attack_start_subtick: int):
        self.attack_profile = parse_attack_profile(atk_profile_yaml)
        self.attack_dict = {
            "Benign"        : benign,
            "ICMP flood"    : icmp_flood,
            "Smurf attack"  : smurf_attack,
            "Coremelt"      : coremelt,
            "DNS amp"       : dns_amp,
            "UDP flood"     : udp_flood,
            "DNS flood"     : dns_flood,
            "NTP amp"       : ntp_amp,
            "SSDP amp"      : ssdp_amp,
            "Memcached amp" : memcached_amp,
            "QUIC amp"      : quic_amp,
            "HTTP flood"    : http_flood,
            "Slowloris"     : slowloris,
            "SYN flood"     : syn_flood,
            "ACK flood"     : ack_flood,
            "RST FIN flood" : rst_fin_flood
        }
        self.attack_key = list(dict.fromkeys(sum([[get_key(x) for x in d['attacks']] if get_key(d) == 'attacks' else [] for d in self.attack_profile], [])))
        self.attack_str_key = []
        for atk in self.attack_key:
            atk_str = atk.split("/")[0]
            if atk_str not in self.attack_dict:
                raise ValueError(f"Invalid attack exists in attack profile '{atk_profile_yaml}.yaml': {atk}")
            if atk_str not in self.attack_str_key:
                self.attack_str_key.append(atk_str)
        self.attack_key = sorted(self.attack_key, key=lambda x: list(self.attack_dict.keys()).index(x.split("/")[0]))
        self.attack_str_key = sorted(self.attack_str_key, key=lambda x: list(self.attack_dict.keys()).index(x))

        self.benign_volume = benign_volume  # Gbps
        self.attack_volume = attack_volume  # Gbps
        self.max_tick, self.ratio, self.rate, self.seq_size, self.seq_count, self.seq_ratio, self.loop_size, self.loop_count, self.loop_ratio, self.loop_rate \
            = get_rate(self.attack_profile, self.attack_key, self.attack_volume, attack_tick_to_subtick, attack_start_subtick)  # rate in B
        self.benign_byte_used = {}
        self.refresh_cycle_per_attack = refresh_cycle_per_attack
        self.tick_divisor = tick_divisor
        self.attack_tick_to_subtick = attack_tick_to_subtick
        self.attack_start_subtick = attack_start_subtick

        self.benign_flowkey = generate_benign_flowkey(benign_unique_flowkey)
        self.benign_flowkey = [[src_ip, src_port, dst_ip, dst_port, "BEGIN", None, None] for src_ip, src_port, dst_ip, dst_port in self.benign_flowkey] # 4-tuple, TCP_state, TCP_type, TCP_dst_port
        self.attack_ip = [[ip, [], [], -1, -1, -1] for ip in generate_attack_ip(attack_unique_ip)]   # ip, loop_size, loop_count, loop_count_index, loop_count_count, loop_last_subtick
        self.attack_ip_division = {atk: [divide_list_by_ratio(attack_unique_ip, [l[i] - l[i-1] for i in range(len(l)) if i > 0]) for l in self.ratio[atk]] for atk in self.ratio}
        self.attack_seq_ip_division = {atk: [divide_list_by_ratio(attack_unique_ip, [l[i] - l[i-1] for i in range(len(l)) if i > 0]) for l in self.seq_ratio[atk]] for atk in self.seq_ratio}
        self.attack_loop_ip_division = {atk: [divide_list_by_ratio(attack_unique_ip, [l[i] - l[i-1] for i in range(len(l)) if i > 0]) for l in self.loop_ratio[atk]] for atk in self.loop_ratio}
        self.victim_ip = pkt.ip_to_bytes("192.168.0.1")
        self.traffic: dict[int, list[pkt.Packet]] = dict()

    def add_to_traffic(self, packet: pkt.Packet):
        tick = packet.tick
        if tick not in self.traffic:
            self.traffic[tick] = []
        self.traffic[tick].append(packet)

    # Wrapper function for iterative generation of attack traffic
    def iterative_generate(self, atk: str, initial_left_volume: float, current_subtick: int, attack_ip_division: list[int]) -> list[pkt.Packet]:
        attack_ip = sum([[x for x, _, _, _, _, _ in self.attack_ip[attack_ip_division[2*i]: attack_ip_division[2*i+1]]] for i in range(len(attack_ip_division)//2)], [])
        packets = []
        left_volume = initial_left_volume
        while left_volume > 0:
            packet_list = self.attack_dict[atk](current_subtick, self.victim_ip, self.benign_flowkey, attack_ip, 0)
            for p in packet_list:
                p.count = -1
                if p.attack_type == 0 and p.tick != current_subtick:
                    if p.tick not in self.benign_byte_used:
                        self.benign_byte_used[p.tick] = 0
                    self.benign_byte_used[p.tick] += p.packet_size
                    self.add_to_traffic(p)
                else:
                    left_volume -= p.packet_size
                    packets.append(p)
        return packets

    def iterative_generate_seq(self, atk: str, psize: list[int], pcount: list[int], current_subtick: int, attack_ip_division: list[int]) -> list[pkt.Packet]:
        attack_ip = sum([[x for x, _, _, _, _, _ in self.attack_ip[attack_ip_division[2*i]: attack_ip_division[2*i+1]]] for i in range(len(attack_ip_division)//2)], [])
        packets = []
        for i in range(len(attack_ip)):
            count = 1
            for j in range(len(psize)):
                left_count = pcount[j]
                while left_count > 0:
                    packet_list = self.attack_dict[atk](current_subtick, self.victim_ip, self.benign_flowkey, [attack_ip[i]], psize[j])
                    for p in packet_list:
                        p.count = count
                        count += 1
                        left_count -= 1
                        packets.append(p)
        return packets

    def iterative_generate_seq_real(self, atk: str, psize: list[int], pcount: list[int], current_subtick: int, attack_ip_division: list[int]) -> list[list[pkt.Packet]]:
        attack_ip = sum([[x for x, _, _, _, _, _ in self.attack_ip[attack_ip_division[2*i]: attack_ip_division[2*i+1]]] for i in range(len(attack_ip_division)//2)], [])
        packets_list = [[] for _ in range(len(attack_ip))]
        for i in range(len(attack_ip)):
            count = 1
            for j in range(len(psize)):
                left_count = pcount[j]
                while left_count > 0:
                    packet_list = self.attack_dict[atk](current_subtick, self.victim_ip, self.benign_flowkey, [attack_ip[i]], psize[j])
                    for p in packet_list:
                        p.count = count
                        count += 1
                        left_count -= 1
                        packets_list[i].append(p)
        return packets_list

    def iterative_generate_loop(self, atk: str, psize: list[int], pcount: list[int], initial_left_volume: float, current_subtick: int, attack_ip_division: list[int]) -> list[pkt.Packet]:
        attack_ip_indices = sum([list(range(attack_ip_division[2*i], attack_ip_division[2*i+1])) for i in range(len(attack_ip_division)//2)], [])
        packets = []
        left_volume = initial_left_volume
        while left_volume > 0 and any(x > 0 for x in pcount):
            index = choice(attack_ip_indices)
            ip, loop_size, loop_count, loop_count_index, loop_count_count, loop_last_subtick = self.attack_ip[index]
            if loop_last_subtick != current_subtick:
                if loop_size != psize or loop_count != pcount:
                    loop_size, loop_count, loop_count_index, loop_count_count = psize, pcount, 0, 0
                elif loop_last_subtick // (self.tick_divisor*self.refresh_cycle_per_attack[atk]) != current_subtick // (self.tick_divisor*self.refresh_cycle_per_attack[atk]):
                    loop_count_index, loop_count_count = 0, 0
                loop_last_subtick = current_subtick
            while loop_count_count >= loop_count[loop_count_index]:
                loop_count_index = (loop_count_index + 1) % len(loop_count)
                loop_count_count = 0
            size = loop_size[loop_count_index]
            loop_count_count += 1
            self.attack_ip[index] = [ip, loop_size, loop_count, loop_count_index, loop_count_count, loop_last_subtick]

            packet_list = self.attack_dict[atk](current_subtick, self.victim_ip, self.benign_flowkey, [ip], size)
            for p in packet_list:
                p.count = -1
                left_volume -= p.packet_size
                packets.append(p)
        return packets

    # Generate attack traffic based on attack profile
    def generate(self, subtick: int):
        # Generate attack traffic
        packets_list = []
        if 0 <= subtick < (self.max_tick+1)*self.attack_tick_to_subtick + self.attack_start_subtick:
            for atk in self.attack_key:
                atk_str = atk.split("/")[0]
                packets_list.append(self.iterative_generate(atk_str, self.rate[atk][subtick], subtick, self.attack_ip_division[atk][subtick]))

                packets_list.append(self.iterative_generate_seq(atk_str, self.seq_size[atk][subtick], self.seq_count[atk][subtick], subtick, self.attack_seq_ip_division[atk][subtick]))
                # packets_list += self.iterative_generate_seq_real(atk_str, self.seq_size[atk][subtick], self.seq_count[atk][subtick], subtick, self.attack_seq_ip_division[atk][subtick])
                packets_list.append(self.iterative_generate_loop(atk_str, self.loop_size[atk][subtick], self.loop_count[atk][subtick], self.loop_rate[atk][subtick], subtick, self.attack_loop_ip_division[atk][subtick]))

        # Generate benign traffic
        benign_byte_volume = self.benign_volume * 125 * 1000 * 1000 / self.attack_tick_to_subtick
        if subtick in self.benign_byte_used:
            benign_byte_volume -= self.benign_byte_used[subtick]
        benign_packets = self.iterative_generate("Benign", benign_byte_volume, subtick, [0, 0])
        if subtick in self.traffic:
            packets_list.append(self.traffic[subtick])
        packets_list.append(benign_packets)

        self.traffic[subtick] = combine_lists(packets_list)

    def generate_all(self, tick_divisor: int):
        num_tick = ((self.max_tick+1)*self.attack_tick_to_subtick + self.attack_start_subtick - 1)//tick_divisor + 1
        for tick in range(num_tick):
            for subtick in range(tick_divisor):
                current_subtick = tick * self.attack_tick_to_subtick + subtick
                self.generate(current_subtick)

    def delete_traffic(self, subtick: int):
        traffic = self.traffic.pop(subtick)
        traffic.clear()

####################
#  Benign Traffic  #
####################

def benign_packet_size() -> int:
        prob = random()
        if prob < 0.35:
            packet_size = randint(smallest_psize, 128)
        elif prob < 0.35 + 0.20:
            packet_size = randint(129, 512)
        elif prob < 0.35 + 0.20 + 0.20:
            packet_size = randint(513, 1023)
        elif prob < 0.35 + 0.20 + 0.20 + 0.15:
            packet_size = randint(1024, 1280)
        else:
            packet_size = randint(1281, largest_psize)
        return packet_size

# packet_stats gave ["SYN", "SNACK", "ACK", "FIN", "RST"]: [0.04654168326127674, 0.0059460687168807575, 0.9427417974641836, 0.0, 0.004764852375948292]
# ratio of ["SYN", "SNACK", "ACK", "FIN", "RST"]: [0.03398531571863376, 0.03334388664318601, 0.9056742604772693, 0.017182507696874554, 0.00981402946403635]
def benign_TCP_state(tcp_state: str) -> tuple[str, bool]:
    prob = random()
    if tcp_state == "BEGIN" or tcp_state == "ACK_FIN2":
        return "SYN", False
    elif tcp_state == "SYN":
        if prob < 0.99:
            return "SNACK", True
        else:
            return "RST", False
    elif tcp_state == "SNACK":
        if prob < 0.99:
            return "ACK", False
        else:
            return "RST", False
    elif tcp_state == "ACK":
        if prob < 0.98:
            return "ACK", False
        elif prob < 0.98 + 0.01:
            return "FIN1", False
        else:
            return "RST", False
    elif tcp_state == "FIN1":
        if prob < 0.99:
            return "ACK_FIN1", True
        else:
            return "RST", False
    elif tcp_state == "ACK_FIN1":
        if prob < 0.99:
            return "FIN2", True
        else:
            return "RST", False
    elif tcp_state == "FIN2":
        if prob < 0.99:
            return "ACK_FIN2", False
        else:
            return "RST", False
    elif tcp_state == "RST":
        if prob < 0.99:
            return "SYN", False
        else:
            return "RST", False
    else:
        raise ValueError(f"No TCP state named: {tcp_state}")

def benign_TCP_type(dst_port: bytes) -> tuple[str, bytes]:
    prob = random()
    if prob < 0.0008:
        return "_DNS", pkt.int_to_bytes(53, 2)
    elif prob < 0.0008 + 0.1013:
        return "_HTTP", pkt.int_to_bytes(80, 2)
    elif prob < 0.0008 + 0.1013 + 0.7444:
        return "_HTTPS", pkt.int_to_bytes(443, 2)
    elif prob < 0.0008 + 0.1013 + 0.7444 + 0.0001:
        return "_Memcached", pkt.int_to_bytes(11211, 2)
    else:
        return "", dst_port

def benign(tick: int, victim_ip: bytes, benign_flowkey: list, attack_ip: list[bytes], psize: int) -> list[pkt.Packet]:
    index = choice(range(len(benign_flowkey)))
    src_ip, src_port, dst_ip, dst_port, old_tcp_state, tcp_type, tcp_dst_port = benign_flowkey[index]
    prob = random()
    packets = []
    if prob < 0.80:
        tcp_state, src_dst_reverse = benign_TCP_state(old_tcp_state)
        if tcp_state == "SYN":
            tcp_type, tcp_dst_port = benign_TCP_type(dst_port)
            benign_flowkey[index][5] = tcp_type
            benign_flowkey[index][6] = tcp_dst_port
        benign_flowkey[index][4] = tcp_state
        (src_ip, src_port, dst_ip, tcp_dst_port) = (dst_ip, tcp_dst_port, src_ip, src_port) if src_dst_reverse else (src_ip, src_port, dst_ip, tcp_dst_port)
        if old_tcp_state == "ACK" and tcp_state == "ACK":
            if tcp_type == "_DNS" or tcp_type == "_Memcached":
                packets.append(pkt.Packet(src_ip, src_port, dst_ip, tcp_dst_port, f"TCP_{tcp_state}{tcp_type}Q", benign_packet_size(), tick, 0))
                packets.append(pkt.Packet(dst_ip, tcp_dst_port, src_ip, src_port, f"TCP_{tcp_state}{tcp_type}R", benign_packet_size(), tick+1, 0))
            else:
                (src_ip, src_port, dst_ip, tcp_dst_port) = (dst_ip, tcp_dst_port, src_ip, src_port) if random() < 0.5 else (src_ip, src_port, dst_ip, tcp_dst_port)
                packets.append(pkt.Packet(src_ip, src_port, dst_ip, tcp_dst_port, f"TCP_{tcp_state}{tcp_type}", benign_packet_size(), tick, 0))
        else:
            packets.append(pkt.Packet(src_ip, src_port, dst_ip, tcp_dst_port, f"TCP_{tcp_state}{tcp_type}", randint(smallest_psize, 80), tick, 0))
    elif prob < 0.80 + 0.18:
        udp_prob = random()
        if udp_prob < 0.30:                                         # DNS
            packets.append(pkt.Packet(src_ip, src_port, dst_ip, pkt.int_to_bytes(53, 2), "UDP_DNSQ", benign_packet_size(), tick, 0))
            packets.append(pkt.Packet(dst_ip, pkt.int_to_bytes(53, 2), src_ip, src_port, "UDP_DNSR", benign_packet_size(), tick+1, 0))
        elif udp_prob < 0.30 + 0.02:                                # QUIC1
            packets.append(pkt.Packet(src_ip, src_port, dst_ip, pkt.int_to_bytes(80, 2), "UDP", benign_packet_size(), tick, 0))
            packets.append(pkt.Packet(dst_ip, pkt.int_to_bytes(80, 2), src_ip, src_port, "UDP", benign_packet_size(), tick+1, 0))
        elif udp_prob < 0.30 + 0.02 + 0.35:                         # QUIC2
            packets.append(pkt.Packet(src_ip, src_port, dst_ip, pkt.int_to_bytes(443, 2), "UDP", benign_packet_size(), tick, 0))
            packets.append(pkt.Packet(dst_ip, pkt.int_to_bytes(443, 2), src_ip, src_port, "UDP", benign_packet_size(), tick+1, 0))
        elif udp_prob < 0.30 + 0.02 + 0.35 + 0.03:                  # NTP
            packets.append(pkt.Packet(src_ip, src_port, dst_ip, pkt.int_to_bytes(123, 2), "UDP_NTP", benign_packet_size(), tick, 0))
            packets.append(pkt.Packet(dst_ip, pkt.int_to_bytes(123, 2), src_ip, src_port, "UDP_NTP", benign_packet_size(), tick+1, 0))
        elif udp_prob < 0.30 + 0.02 + 0.35 + 0.03 + 0.03:           # SSDP
            packets.append(pkt.Packet(src_ip, src_port, dst_ip, pkt.int_to_bytes(1900, 2), "UDP_SSDP", benign_packet_size(), tick, 0))
            packets.append(pkt.Packet(dst_ip, pkt.int_to_bytes(1900, 2), src_ip, src_port, "UDP_SSDP", benign_packet_size(), tick+1, 0))
        elif udp_prob < 0.30 + 0.02 + 0.35 + 0.03 + 0.03 + 0.02:    # memcached
            server_ip = choice(memcached_servers)
            packets.append(pkt.Packet(src_ip, src_port, server_ip, pkt.int_to_bytes(11211, 2), "UDP", benign_packet_size(), tick, 0))
            packets.append(pkt.Packet(server_ip, pkt.int_to_bytes(11211, 2), src_ip, src_port, "UDP", benign_packet_size(), tick+1, 0))
        else:
            packets.append(pkt.Packet(src_ip, src_port, dst_ip, dst_port, "UDP", benign_packet_size(), tick, 0))
    else:
        packets.append(pkt.Packet(src_ip, pkt.int_to_bytes(0, 2), dst_ip, pkt.int_to_bytes(0, 2), "ICMP_request", benign_packet_size(), tick, 0))
        packets.append(pkt.Packet(dst_ip, pkt.int_to_bytes(0, 2), src_ip, pkt.int_to_bytes(0, 2), "ICMP_reply", benign_packet_size(), tick+1, 0))
    return packets

####################
#   DDoS Attacks   #
####################
# ICMP flooding
def icmp_flood(tick: int, victim_ip: bytes, benign_flowkey: list, attack_ip: list[bytes], psize: int) -> list[pkt.Packet]:
    atk_type = 1
    src_ip = choice(attack_ip)
    psize = 84 if psize == 0 else psize
    packet = pkt.Packet(src_ip, pkt.int_to_bytes(0, 2), victim_ip, pkt.int_to_bytes(0, 2), "ICMP_request", psize, tick, atk_type)
    return [packet]

# Smurf attack
def smurf_attack(tick: int, victim_ip: bytes, benign_flowkey: list, attack_ip: list[bytes], psize: int) -> list[pkt.Packet]:
    atk_type = 2
    src_ip = choice(attack_ip)
    psize = 84 if psize == 0 else psize
    packet = pkt.Packet(src_ip, pkt.int_to_bytes(0, 2), victim_ip, pkt.int_to_bytes(0, 2), "ICMP_reply", psize, tick, atk_type)
    return [packet]

# Coremelt attack
def coremelt(tick: int, victim_ip: bytes, benign_flowkey: list, attack_ip: list[bytes], psize: int) -> list[pkt.Packet]:
    atk_type = 3
    src_ip = choice(attack_ip)
    psize = randint(512, 1024) if psize == 0 else psize
    # UDP/TCP ratio
    udp_ratio = 0.7
    protocol = "UDP" if random() < udp_ratio else "TCP"
    packet = pkt.Packet(src_ip, pkt.int_to_bytes(randint(1024, 65535), 2), victim_ip, pkt.int_to_bytes(randint(1024, 65535), 2), protocol, psize, tick, atk_type)
    return [packet]

# DNS amplification attack
def dns_amp(tick: int, victim_ip: bytes, benign_flowkey: list, attack_ip: list[bytes], psize: int) -> list[pkt.Packet]:
    # IP pool not used but kept for consistency for iterative_generate()
    atk_type = 4
    resolver_ip = choice(dns_resolvers)
    psize = randint(2048, 65536) if psize == 0 else psize
    # generate DNS amplification packet
    packets = split_packet(resolver_ip, pkt.int_to_bytes(53, 2), victim_ip, pkt.int_to_bytes(randint(1024, 65535), 2), "UDP_DNSR", psize, tick, atk_type)
    return packets

# UDP flooding
def udp_flood(tick: int, victim_ip: bytes, benign_flowkey: list, attack_ip: list[bytes], psize: int) -> list[pkt.Packet]:
    atk_type = 5
    src_ip = choice(attack_ip)
    psize = randint(512, 1024) if psize == 0 else psize
    packet = pkt.Packet(src_ip, pkt.int_to_bytes(randint(1024, 65535), 2), victim_ip, pkt.int_to_bytes(randint(1024, 65535), 2), "UDP", psize, tick, atk_type)
    return [packet]

# DNS flooding
def dns_flood(tick: int, victim_ip: bytes, benign_flowkey: list, attack_ip: list[bytes], psize: int) -> list[pkt.Packet]:
    atk_type = 6
    src_ip = choice(attack_ip)
    psize = randint(512, 1024) if psize == 0 else psize
    packet = pkt.Packet(src_ip, pkt.int_to_bytes(randint(1024, 65535), 2), victim_ip, pkt.int_to_bytes(53, 2), "UDP_DNSQ", psize, tick, atk_type)
    return [packet]

# NTP amplification attack
def ntp_amp(tick: int, victim_ip: bytes, benign_flowkey: list, attack_ip: list[bytes], psize: int) -> list[pkt.Packet]:
    atk_type = 7
    resolver_ip = choice(ntp_servers)
    psize = randint(512, 1024) if psize == 0 else psize
    packet = pkt.Packet(resolver_ip, pkt.int_to_bytes(123, 2), victim_ip, pkt.int_to_bytes(randint(1024, 65535), 2), "UDP_NTP", psize, tick, atk_type)
    return [packet]

# SSDP amplification attack
def ssdp_amp(tick: int, victim_ip: bytes, benign_flowkey: list, attack_ip: list[bytes], psize: int) -> list[pkt.Packet]:
    atk_type = 8
    upnp_ip = choice(attack_ip)
    psize = randint(512, 1024) if psize == 0 else psize
    packet = pkt.Packet(upnp_ip, pkt.int_to_bytes(1900, 2), victim_ip, pkt.int_to_bytes(randint(1024, 65535), 2), "UDP_SSDP", psize, tick, atk_type)
    return [packet]

# Memcached amplification attack
def memcached_amp(tick: int, victim_ip: bytes, benign_flowkey: list, attack_ip: list[bytes], psize: int) -> list[pkt.Packet]:
    atk_type = 9
    server_ip = choice(memcached_servers)
    psize = randint(512, 1024) if psize == 0 else psize
    # Attacket spoof ip and request HTTP_GET to memcached server
    packet = pkt.Packet(server_ip, pkt.int_to_bytes(11211, 2), victim_ip, pkt.int_to_bytes(randint(1024, 65535), 2), "TCP_ACK", psize, tick, atk_type)
    return [packet]

# QUIC amplification attack
def quic_amp(tick: int, victim_ip: bytes, benign_flowkey: list, attack_ip: list[bytes], psize: int) -> list[pkt.Packet]:
    atk_type = 10
    quic_server_ip = choice(quic_servers)
    psize = 428 if psize == 0 else psize
    src_port = 80 if random() < 0.5 else 443
    packet = pkt.Packet(quic_server_ip, pkt.int_to_bytes(src_port, 2), victim_ip, pkt.int_to_bytes(randint(1024, 65535), 2), "UDP", psize, tick, atk_type)
    return [packet]

# HTTP GET/POST flooding
def http_flood(tick: int, victim_ip: bytes, benign_flowkey: list, attack_ip: list[bytes], psize: int) -> list[pkt.Packet]:
    atk_type = 11
    src_ip = choice(attack_ip)
    psize = randint(512, 1024) if psize == 0 else psize
    protocol_ratio = 0.5
    (protocol_type, dst_port) = ("TCP_ACK_HTTP", 80) if random() < protocol_ratio else ("TCP_ACK_HTTPS", 443)
    packet = pkt.Packet(src_ip, pkt.int_to_bytes(randint(1024, 65535), 2), victim_ip, pkt.int_to_bytes(dst_port, 2), protocol_type, psize, tick, atk_type)
    return [packet]

# Slowloris attack
def slowloris(tick: int, victim_ip: bytes, benign_flowkey: list, attack_ip: list[bytes], psize: int) -> list[pkt.Packet]:
    atk_type = 12
    src_ip = choice(attack_ip)
    psize = smallest_psize if psize == 0 else psize
    protocol_ratio = 0.5
    (protocol_type, dst_port) = ("TCP_SYN_HTTP", 80) if random() < protocol_ratio else ("TCP_SYN_HTTPS", 443)
    packet = pkt.Packet(src_ip, pkt.int_to_bytes(randint(1024, 65535), 2), victim_ip, pkt.int_to_bytes(dst_port, 2), protocol_type, psize, tick, atk_type)
    return [packet]

# TCP SYN flooding
def syn_flood(tick: int, victim_ip: bytes, benign_flowkey: list, attack_ip: list[bytes], psize: int) -> list[pkt.Packet]:
    atk_type = 13
    src_ip = choice(attack_ip)
    psize = smallest_psize if psize == 0 else psize
    packet = pkt.Packet(src_ip, pkt.int_to_bytes(randint(1024, 65535), 2), victim_ip, pkt.int_to_bytes(randint(1024, 65535), 2), "TCP_SYN", psize, tick, atk_type)
    return [packet]

# TCP ACK flooding
def ack_flood(tick: int, victim_ip: bytes, benign_flowkey: list, attack_ip: list[bytes], psize: int) -> list[pkt.Packet]:
    atk_type = 14
    src_ip = choice(attack_ip)
    psize = smallest_psize if psize == 0 else psize
    packet = pkt.Packet(src_ip, pkt.int_to_bytes(randint(1024, 65535), 2), victim_ip, pkt.int_to_bytes(randint(1024, 65535), 2), "TCP_ACK", psize, tick, atk_type)
    return [packet]

# TCP RST/FIN flooding
def rst_fin_flood(tick: int, victim_ip: bytes, benign_flowkey: list, attack_ip: list[bytes], psize: int) -> list[pkt.Packet]:
    atk_type = 15
    src_ip = choice(attack_ip)
    psize = smallest_psize if psize == 0 else psize
    rst_ratio = 0.5
    protocol_type = "TCP_FIN" if random() < rst_ratio else "TCP_RST"
    packet = pkt.Packet(src_ip, pkt.int_to_bytes(randint(1024, 65535), 2), victim_ip, pkt.int_to_bytes(randint(1024, 65535), 2), protocol_type, psize, tick, atk_type)
    return [packet]

# Minor functions
def get_key(d: Dict):
    if len(d) == 1:
        return list(d.keys())[0]
    else:
        raise ValueError(f"Invalid dictionary to get a single key: {d}")

def parse_attack_profile(filename = "profile1") -> List[Dict]:
    path = f"{os.path.dirname(os.path.realpath(__file__))}/../atk_profile/"
    if filename != "profile1":
        path += f"{filename}.yaml"
    else:
        # default profile
        path += "profile1.yaml" 

    with open(path, "r") as file:
        attack_profile = yaml.safe_load(file)
    return attack_profile

def get_rate(attack_profile: list[dict], attack_key: list[str], attack_volume: int, attack_tick_to_subtick: int, attack_start_subtick: int) \
             -> tuple[int, dict[str, list[list[int | float]]], dict[str, list[float]], dict[str, list[list[int]]], dict[str, list[list[int]]], dict[str, list[list[int | float]]], dict[str, list[list[int]]], dict[str, list[list[int]]], dict[str, list[list[int | float]]], dict[str, list[float]]]:
    max_tick = -1
    for d in attack_profile:
        key = get_key(d)
        if key == "tick":
            if isinstance(d["tick"], int):
                current_max_tick = d["tick"]
                if d["tick"] < 0:
                    raise ValueError(f"Tick should be nonnegative: {d['tick']}")
            elif isinstance(d["tick"], list) and all(isinstance(x, int) for x in d["tick"]):
                current_max_tick = max(d["tick"])
                if min(d["tick"]) < 0:
                    raise ValueError(f"Tick should be nonnegative: {d['tick']}")
            else:
                raise ValueError(f"Invalid type for tick: {d['tick']}")
            max_tick = max(max_tick, current_max_tick)
    if max_tick < 0:
        raise ValueError(f"Max tick should be nonnegative: {max_tick}")

    ratio = {atk: [[0.0, 0.0] for _ in range((attack_tick_to_subtick*(max_tick+1) + attack_start_subtick))] for atk in attack_key}
    rate = {atk: [0.0] * (attack_tick_to_subtick*(max_tick+1) + attack_start_subtick) for atk in attack_key}
    seq_size = {atk: [[] for _ in range((attack_tick_to_subtick*(max_tick+1) + attack_start_subtick))] for atk in attack_key}
    seq_count = {atk: [[] for _ in range((attack_tick_to_subtick*(max_tick+1) + attack_start_subtick))] for atk in attack_key}
    seq_ratio = {atk: [[0.0, 0.0] for _ in range((attack_tick_to_subtick*(max_tick+1) + attack_start_subtick))] for atk in attack_key}
    loop_size = {atk: [[] for _ in range((attack_tick_to_subtick*(max_tick+1) + attack_start_subtick))] for atk in attack_key}
    loop_count = {atk: [[] for _ in range((attack_tick_to_subtick*(max_tick+1) + attack_start_subtick))] for atk in attack_key}
    loop_ratio = {atk: [[0.0, 0.0] for _ in range((attack_tick_to_subtick*(max_tick+1) + attack_start_subtick))] for atk in attack_key}
    loop_rate = {atk: [0.0] * (attack_tick_to_subtick*(max_tick+1) + attack_start_subtick) for atk in attack_key}
    current_ticks = []
    for d in attack_profile:
        key = get_key(d)
        if key == "tick":
            if isinstance(d["tick"], int):
                current_ticks.append(d["tick"])
            elif isinstance(d["tick"], list) and all(isinstance(x, int) for x in d["tick"]):
                current_ticks += d["tick"]
            else:
                raise ValueError(f"Invalid type for tick: {d['tick']}")
        elif key == "attacks":
            for current_tick in current_ticks:
                for i in range(attack_tick_to_subtick):
                    current_subtick = attack_start_subtick + current_tick*attack_tick_to_subtick + i
                    for atk in d["attacks"]:
                        atk_type = get_key(atk)
                        if 'ratio' in atk[atk_type]:
                            atk_ratio = atk[atk_type]['ratio']
                            if isinstance(atk_ratio, list):
                                if len(atk_ratio) % 2 == 0 and all(isinstance(x, int) or isinstance(x, float) for x in atk_ratio) and leq(0.0, atk_ratio[0]) and all(leq(atk_ratio[i], atk_ratio[i+1]) for i in range(len(atk_ratio)-1)) and leq(atk_ratio[-1], 1.0):
                                    ratio[atk_type][current_subtick] = atk_ratio
                                elif all(isinstance(l, list) and len(l) % 2 == 0 and all(isinstance(x, int) or isinstance(x, float) for x in l) and leq(0.0, l[0]) and all(leq(l[i], l[i+1]) for i in range(len(l)-1)) and leq(l[-1], 1.0) for l in atk_ratio) and len(atk_ratio) == attack_tick_to_subtick:
                                    ratio[atk_type][current_subtick] = atk_ratio[i]
                                else:
                                    raise ValueError(f"Invalid type for ratio: {atk_ratio}")
                            else:
                                raise ValueError(f"Invalid type for ratio: {atk_ratio}")
                        if 'rate ratio' in atk[atk_type]:
                            atk_rate_ratio = atk[atk_type]['rate ratio']
                            if (isinstance(atk_rate_ratio, int) or isinstance(atk_rate_ratio, float)) and leq(0.0, atk_rate_ratio) and leq(atk_rate_ratio, 1.0):
                                rate[atk_type][current_subtick] += atk_rate_ratio * attack_volume * 125 * 1000 * 1000 / attack_tick_to_subtick
                            elif isinstance(atk_rate_ratio, list) and all((isinstance(x, int) or isinstance(x, float)) and leq(0.0, x) and leq(x, 1.0) for x in atk_rate_ratio) and len(atk_rate_ratio) == attack_tick_to_subtick:
                                rate[atk_type][current_subtick] += atk_rate_ratio[i] * attack_volume * 125 * 1000 * 1000 / attack_tick_to_subtick
                            else:
                                raise ValueError(f"Invalid type for rate ratio: {atk_rate_ratio}")
                        if 'seq size' in atk[atk_type]:
                            atk_seq_size = atk[atk_type]['seq size']
                            if isinstance(atk_seq_size, list):
                                if all(isinstance(x, int) and smallest_psize <= x <= largest_psize for x in atk_seq_size):
                                    seq_size[atk_type][current_subtick] = atk_seq_size
                                elif all(isinstance(l, list) and all(isinstance(x, int) and smallest_psize <= x <= largest_psize for x in l) for l in atk_seq_size) and len(atk_seq_size) == attack_tick_to_subtick:
                                    seq_size[atk_type][current_subtick] = atk_seq_size[i]
                                else:
                                    raise ValueError(f"Invalid type for seq size: {atk_seq_size}")
                            else:
                                raise ValueError(f"Invalid type for seq size: {atk_seq_size}")
                        if 'seq count' in atk[atk_type]:
                            atk_seq_count = atk[atk_type]['seq count']
                            if isinstance(atk_seq_count, list):
                                if all(isinstance(x, int) and x >= 0 for x in atk_seq_count):
                                    seq_count[atk_type][current_subtick] = atk_seq_count
                                elif all(isinstance(l, list) and all(isinstance(x, int) and x >= 0 for x in l) for l in atk_seq_count) and len(atk_seq_count) == attack_tick_to_subtick:
                                    seq_count[atk_type][current_subtick] = atk_seq_count[i]
                                else:
                                    raise ValueError(f"Invalid type for seq count: {atk_seq_count}")
                            else:
                                raise ValueError(f"Invalid type for seq count: {atk_seq_count}")
                        if len(seq_size[atk_type][current_subtick]) != len(seq_count[atk_type][current_subtick]):
                            raise ValueError(f"Length of seq size and seq count of attack {atk_type} differs on tick {current_tick} (subtick {current_subtick}): {seq_size[atk_type][current_subtick]} and {seq_count[atk_type][current_subtick]}")
                        if 'seq ratio' in atk[atk_type]:
                            atk_seq_ratio = atk[atk_type]['seq ratio']
                            if isinstance(atk_seq_ratio, list):
                                if len(atk_seq_ratio) % 2 == 0 and all(isinstance(x, int) or isinstance(x, float) for x in atk_seq_ratio) and leq(0.0, atk_seq_ratio[0]) and all(leq(atk_seq_ratio[i], atk_seq_ratio[i+1]) for i in range(len(atk_seq_ratio)-1)) and leq(atk_seq_ratio[-1], 1.0):
                                    seq_ratio[atk_type][current_subtick] = atk_seq_ratio
                                elif all(isinstance(l, list) and len(l) % 2 == 0 and all(isinstance(x, int) or isinstance(x, float) for x in l) and leq(0.0, l[0]) and all(leq(l[i], l[i+1]) for i in range(len(l)-1)) and leq(l[-1], 1.0) for l in atk_seq_ratio) and len(atk_seq_ratio) == attack_tick_to_subtick:
                                    seq_ratio[atk_type][current_subtick] = atk_seq_ratio[i]
                                else:
                                    raise ValueError(f"Invalid type for seq ratio: {atk_seq_ratio}")
                            else:
                                raise ValueError(f"Invalid type for seq ratio: {atk_seq_ratio}")
                        if 'loop size' in atk[atk_type]:
                            atk_loop_size = atk[atk_type]['loop size']
                            if isinstance(atk_loop_size, list):
                                if all(isinstance(x, int) and smallest_psize <= x <= largest_psize for x in atk_loop_size):
                                    loop_size[atk_type][current_subtick] = atk_loop_size
                                elif all(isinstance(l, list) and all(isinstance(x, int) and smallest_psize <= x <= largest_psize for x in l) for l in atk_loop_size) and len(atk_loop_size) == attack_tick_to_subtick:
                                    loop_size[atk_type][current_subtick] = atk_loop_size[i]
                                else:
                                    raise ValueError(f"Invalid type for loop size: {atk_loop_size}")
                            else:
                                raise ValueError(f"Invalid type for loop size: {atk_loop_size}")
                        if 'loop count' in atk[atk_type]:
                            atk_loop_count = atk[atk_type]['loop count']
                            if isinstance(atk_loop_count, list):
                                if all(isinstance(x, int) and x >= 0 for x in atk_loop_count):
                                    loop_count[atk_type][current_subtick] = atk_loop_count
                                elif all(isinstance(l, list) and all(isinstance(x, int) and x >= 0 for x in l) for l in atk_loop_count) and len(atk_loop_count) == attack_tick_to_subtick:
                                    loop_count[atk_type][current_subtick] = atk_loop_count[i]
                                else:
                                    raise ValueError(f"Invalid type for loop count: {atk_loop_count}")
                            else:
                                raise ValueError(f"Invalid type for loop count: {atk_loop_count}")
                        if len(loop_size[atk_type][current_subtick]) != len(loop_count[atk_type][current_subtick]):
                            raise ValueError(f"Length of loop size and loop count of attack {atk_type} differs on tick {current_tick} (subtick {current_subtick}): {loop_size[atk_type][current_subtick]} and {loop_count[atk_type][current_subtick]}")
                        if 'loop ratio' in atk[atk_type]:
                            atk_loop_ratio = atk[atk_type]['loop ratio']
                            if isinstance(atk_loop_ratio, list):
                                if len(atk_loop_ratio) % 2 == 0 and all(isinstance(x, int) or isinstance(x, float) for x in atk_loop_ratio) and leq(0.0, atk_loop_ratio[0]) and all(leq(atk_loop_ratio[i], atk_loop_ratio[i+1]) for i in range(len(atk_loop_ratio)-1)) and leq(atk_loop_ratio[-1], 1.0):
                                    loop_ratio[atk_type][current_subtick] = atk_loop_ratio
                                elif all(isinstance(l, list) and len(l) % 2 == 0 and all(isinstance(x, int) or isinstance(x, float) for x in l) and leq(0.0, l[0]) and all(leq(l[i], l[i+1]) for i in range(len(l)-1)) and leq(l[-1], 1.0) for l in atk_loop_ratio) and len(atk_loop_ratio) == attack_tick_to_subtick:
                                    loop_ratio[atk_type][current_subtick] = atk_loop_ratio[i]
                                else:
                                    raise ValueError(f"Invalid type for loop ratio: {atk_loop_ratio}")
                            else:
                                raise ValueError(f"Invalid type for loop ratio: {atk_loop_ratio}")
                        if 'loop rate ratio' in atk[atk_type]:
                            atk_loop_rate_ratio = atk[atk_type]['loop rate ratio']
                            if (isinstance(atk_loop_rate_ratio, int) or isinstance(atk_loop_rate_ratio, float)) and leq(0.0, atk_loop_rate_ratio) and leq(atk_loop_rate_ratio, 1.0):
                                loop_rate[atk_type][current_subtick] += atk_loop_rate_ratio * attack_volume * 125 * 1000 * 1000 / attack_tick_to_subtick
                            elif isinstance(atk_loop_rate_ratio, list) and all((isinstance(x, int) or isinstance(x, float)) and leq(0.0, x) and leq(x, 1.0) for x in atk_loop_rate_ratio) and len(atk_loop_rate_ratio) == attack_tick_to_subtick:
                                loop_rate[atk_type][current_subtick] += atk_loop_rate_ratio[i] * attack_volume * 125 * 1000 * 1000 / attack_tick_to_subtick
                            else:
                                raise ValueError(f"Invalid type for loop rate ratio: {atk_loop_rate_ratio}")
            current_ticks = []
        else:
            raise ValueError(f"Invalid key in attack profile: {key}")
    return max_tick, ratio, rate, seq_size, seq_count, seq_ratio, loop_size, loop_count, loop_ratio, loop_rate

def generate_attack_ip(n_unique_ip: int) -> list[bytes]:
    distinct_ip = set()
    while len(distinct_ip) < n_unique_ip:
        new_ip = [randint(0, (256**4) - 1) for _ in range(n_unique_ip - len(distinct_ip))]
        distinct_ip.update(new_ip)
    return [pkt.int_to_bytes(ip, 4) for ip in distinct_ip]

def generate_benign_flowkey(n_unique_flowkey: int) -> list[tuple[bytes, bytes, bytes, bytes]]:
    distinct_flowkey = set()
    while len(distinct_flowkey) < n_unique_flowkey:
        new_flowkey = [(randint(0, (256**4) - 1), randint(1, 65535), randint(0, (256**4) - 1), randint(1, 65535)) for _ in range(n_unique_flowkey - len(distinct_flowkey))]
        distinct_flowkey.update(new_flowkey)
    return [[pkt.int_to_bytes(src_ip, 4), pkt.int_to_bytes(src_port, 2), pkt.int_to_bytes(dst_ip, 4), pkt.int_to_bytes(dst_port, 2)] for src_ip, src_port, dst_ip, dst_port in distinct_flowkey]

def split_packet(src_ip: bytes, src_port: bytes, dst_ip: bytes, dst_port: bytes, protocol: str, packet_size: int, tick: int, attack_type) -> list[pkt.Packet]:
    packets = []
    while packet_size > largest_psize:
        packets.append(pkt.Packet(src_ip, src_port, dst_ip, dst_port, protocol, largest_psize, tick, attack_type))
        packet_size -= 1460
    if packet_size > 0:
        packets.append(pkt.Packet(src_ip, src_port, dst_ip, dst_port, protocol, max(packet_size, 64), tick, attack_type))
    return packets

def combine_lists(lists: list[list]):
    result = []
    pointers = [0] * len(lists)  # Initialize pointers for each list

    # Continue until all pointers have reached the end of their respective lists
    while any(pointer < len(lst) for pointer, lst in zip(pointers, lists)):
        # Calculate the weights based on the remaining elements in each list
        remaining_elements = [len(lst) - pointers[i] for i, lst in enumerate(lists)]
        total_remaining = sum(remaining_elements)

        if total_remaining == 0:
            break

        # Calculate selection probabilities proportional to remaining elements
        probabilities = [remaining / total_remaining for remaining in remaining_elements]

        # Select a list index based on the calculated probabilities
        selected_list_index = choices(range(len(lists)), weights=probabilities, k=1)[0]

        # Append the selected element to the result
        result.append(lists[selected_list_index][pointers[selected_list_index]])
        pointers[selected_list_index] += 1

    return result

def divide_list_by_ratio(n: int, r: list) -> list[int]:
    r.append(1-sum(r))
    m = len(r)  # Number of ratios (and thus the number of sublists)

    # Check if we have enough elements to divide (i.e., n >= number of non-zero ratios)
    non_zero_ratios = [ratio for ratio in r if not math.isclose(ratio, 0, abs_tol=1e-07)]
    if n < len(non_zero_ratios):
        raise ValueError("Not enough elements in l to divide based on ratios")

    # First, calculate the initial target sizes for each non-zero ratio
    target_sizes = []
    for ratio in r:
        if math.isclose(ratio, 0, abs_tol=1e-07):
            target_sizes.append(0)  # For ratios close to 0, we assign 0 elements
        else:
            target_sizes.append(max(1, math.floor(n * ratio)))  # Ensure at least 1 element for non-zero ratios

    # Distribute remaining elements to non-zero ratio sublists
    i = 0
    while sum(target_sizes) < n:
        # Skip 0-ratio sublists
        if not math.isclose(r[i % m], 0, abs_tol=1e-07):
            target_sizes[i % m] += 1
        i += 1
    if sum(target_sizes) > n:
        raise ValueError(f"Error on dividing lists: {n} {r[:-1]} {target_sizes}")

    # Create the sublists
    indices = [0]
    for size in target_sizes:
        indices.append(indices[-1] + size)

    return indices[:-1]

def leq(a: float, b: float) -> bool:
    return a < b or math.isclose(a, b, abs_tol=1e-07)


# Global variables
dns_resolvers = [pkt.ip_to_bytes(x) for x in
                 ['208.76.50.50', '208.67.222.222', '176.103.130.130', '81.218.119.11', '149.112.112.112', 
                 '76.76.19.19', '84.200.69.80', '156.154.70.22', '87.118.111.215', '223.6.6.6', 
                 '156.154.70.1', '199.85.127.10', '198.101.242.72', '77.88.8.8', '114.114.114.114', 
                 '93.114.40.185', '176.103.130.131', '208.67.222.123', '1.0.0.1', '210.2.4.8', 
                 '208.67.220.220', '94.140.15.15', '64.6.64.6', '23.253.163.53', '223.5.5.5', 
                 '1.1.1.2', '8.26.56.26', '185.228.168.9', '199.85.126.10', '182.254.116.116', 
                 '114.114.115.115', '156.154.71.1', '89.233.43.71', '37.235.1.174', '1.2.4.8', 
                 '8.8.8.8', '208.67.220.123', '119.29.29.29', '144.144.144.144', '208.76.51.51', 
                 '64.6.65.6', '216.146.35.35', '216.146.36.36', '45.33.97.5', '202.96.209.5', 
                 '185.228.169.9', '180.76.76.76', '8.20.247.20', '8.8.4.4', '84.200.70.40', 
                 '209.88.198.133', '37.235.1.177', '202.96.209.133', '109.69.8.51', '9.9.9.9', 
                 '192.71.245.208', '94.140.14.14', '77.88.8.1', '74.82.42.42', '45.33.97.6', 
                 '91.239.100.100', '156.154.71.22', '1.0.0.2', '1.1.1.1', '76.223.122.150']
                ]

ntp_servers = [pkt.ip_to_bytes(x) for x in
               ['216.239.35.160', '216.239.35.44', '216.239.35.72', '132.163.97.3', '216.239.35.36', 
               '216.239.35.208', '216.239.35.92', '192.5.41.41', '216.239.35.192', '216.239.35.240', 
               '216.239.35.68', '216.239.35.112', '192.43.244.18', '216.239.35.60', '216.239.35.248', 
               '128.138.140.44', '216.239.35.148', '131.107.13.100', '216.239.35.24', '216.239.35.96', 
               '216.239.35.172', '216.239.35.80', '216.239.35.220', '132.163.97.1', '216.239.35.168', 
               '216.239.35.228', '216.239.35.56', '216.239.35.0', '216.239.35.244', '216.239.35.40', 
               '216.239.35.88', '216.239.35.12', '216.239.35.204', '216.239.35.28', '216.239.35.156', 
               '129.6.15.28', '216.239.35.136', '216.239.35.253', '128.4.40.12', '129.6.15.29', 
               '216.239.35.164', '132.163.97.2', '216.239.35.128', '216.239.35.4', '132.163.96.3', 
               '129.6.15.27', '216.239.35.236', '216.239.35.32', '216.239.35.116', '216.239.35.144', 
               '216.239.35.232', '216.239.35.8', '216.239.35.212', '129.6.15.25', '216.239.35.216', 
               '216.239.35.200', '216.239.35.132', '216.239.35.64', '132.163.96.1', '216.239.35.20', 
               '216.239.35.76', '216.239.35.252', '216.239.35.108', '216.239.35.48', '216.239.35.84', 
               '129.6.15.30', '216.239.35.104', '216.239.35.120', '216.239.35.188', '216.239.35.196', 
               '216.239.35.140', '216.239.35.124', '216.239.35.184', '216.239.35.152', '132.163.96.2', 
               '216.239.35.176', '216.239.35.100', '216.239.35.16', '216.239.35.224', '216.239.35.52', 
               '129.6.15.26', '216.239.35.180']
              ]

# 100 ip addresses from "https://github.com/SecOps-Institute/memcached-server-iplist/blob/master/memcached-servers.txt"
memcached_servers = [pkt.ip_to_bytes(x) for x in
                     ['45.58.60.192', '34.195.104.59', '144.168.124.4', '217.23.11.206', '198.50.227.186', 
                     '107.189.35.155', '68.185.57.45', '188.241.155.14', '34.224.89.134', '60.191.17.149', 
                     '208.43.222.101', '120.55.43.237', '121.28.9.11', '101.201.78.200', '162.144.196.181', 
                     '190.98.204.50', '103.243.181.58', '218.97.54.147', '103.99.63.166', '187.108.192.156', 
                     '199.83.212.207', '66.117.8.46', '65.60.22.19', '144.217.113.100', '51.15.74.147', 
                     '47.90.35.7', '115.28.49.166', '60.251.83.156', '115.28.37.116', '185.174.30.214', 
                     '23.104.135.174', '138.201.108.205', '132.148.146.54', '45.252.248.197', '91.215.216.100', 
                     '91.218.229.7', '46.182.217.28', '75.126.166.203', '92.43.114.251', '118.91.131.157', 
                     '198.200.41.113', '23.88.82.146', '178.63.83.133', '180.213.4.222', '123.206.47.31', 
                     '176.38.163.30', '69.87.197.163', '5.153.250.125', '123.57.162.168', '23.244.241.31', 
                     '49.212.204.170', '46.105.60.74', '35.201.153.233', '187.102.165.77', '109.169.76.68', 
                     '213.207.92.120', '184.172.105.100', '212.227.158.179', '5.32.82.235', '118.114.255.23', 
                     '60.190.240.74', '49.50.8.97', '23.244.190.41', '171.221.251.182', '45.61.113.27', 
                     '27.254.172.36', '5.135.224.32', '51.255.113.243', '77.81.120.251', '23.88.82.77', 
                     '41.77.117.26', '201.229.161.92', '82.102.14.32', '200.199.229.76', '66.135.60.174', 
                     '45.32.122.90', '93.187.234.203', '122.114.206.93', '79.98.29.90', '61.161.197.204', 
                     '45.114.94.202', '52.67.226.67', '91.121.68.84', '103.246.17.68', '45.33.43.226', 
                     '185.174.31.152', '167.114.0.46', '220.226.210.92', '85.204.97.113', '103.45.99.203', 
                     '162.247.154.53', '109.236.90.173', '94.23.173.137', '150.129.216.8', '119.29.19.85']
                    ]

# IP lists on https://quic.cloud/ips
quic_servers = [pkt.ip_to_bytes(x) for x in
                ['156.67.218.140', '38.114.121.40', '188.64.184.71', '66.42.124.101', '162.254.117.80', 
                '199.59.247.242', '38.101.149.196', '147.78.3.13', '216.250.96.181', '204.10.163.237', 
                '108.61.158.223', '185.126.237.129', '91.201.67.57', '41.223.52.170', '155.138.221.81', 
                '103.28.90.190', '18.192.146.200', '81.31.156.246', '45.32.210.159', '149.248.44.108', 
                '185.212.169.91', '136.243.106.228', '207.148.121.96', '92.118.205.75', '192.99.38.117', 
                '201.182.97.70', '103.146.63.42', '185.228.26.40', '31.131.4.244', '5.189.146.228', 
                '149.28.47.113', '213.184.85.245', '190.92.176.5', '158.51.123.249', '145.239.252.65', 
                '69.50.95.216', '185.116.60.231', '67.220.95.23', '211.23.143.87', '163.47.21.168', 
                '34.249.110.197', '93.95.227.66', '45.124.65.86', '103.152.118.219', '45.77.148.74', 
                '65.20.75.178', '38.54.79.187', '38.60.253.237', '70.34.205.229', '146.88.239.197', 
                '178.17.171.177', '5.134.119.194', '45.63.67.181', '27.131.75.40', '163.182.174.161', 
                '51.79.221.227', '102.221.36.99', '109.248.43.195', '86.105.14.231', '54.36.103.97', 
                '65.21.81.50', '209.124.84.191', '45.248.77.61', '178.22.124.251', '51.81.33.156', 
                '86.105.14.232', '65.108.104.232', '45.32.123.201', '178.255.220.12', '46.250.220.133', 
                '167.71.185.204', '45.77.233.177', '188.172.229.113', '51.81.186.219', '202.61.226.253', 
                '45.32.77.223', '194.36.144.221', '103.152.118.72', '81.31.156.245', '141.164.38.65', 
                '91.228.7.67', '167.88.61.211', '216.238.106.164', '65.21.81.51', '162.254.118.29', 
                '45.32.183.112', '27.131.75.41', '45.132.244.92', '64.176.4.251', '23.150.248.180', 
                '45.32.169.55', '79.172.239.249', '104.244.77.37', '157.90.154.114', '149.28.85.239', 
                '152.228.171.66', '49.12.102.29', '185.53.57.89', '61.219.247.87', '38.54.42.235', 
                '202.182.123.93', '164.52.202.100', '102.221.36.98', '188.172.228.182', '135.148.120.32', 
                '191.96.101.140', '170.249.218.98', '31.22.115.186', '172.111.38.73', '195.231.17.141', 
                '5.188.183.13', '103.188.22.12', '103.75.117.169', '213.183.48.170', '213.159.1.75', 
                '198.38.89.73', '64.227.16.93', '34.247.229.180', '38.54.30.31', '94.75.232.90', 
                '185.53.57.40', '178.22.124.247', '41.185.29.210', '45.76.252.131', '83.229.71.151', 
                '209.208.26.218', '61.219.247.90', '185.205.187.233', '192.248.156.201', '5.134.119.103', 
                '103.164.203.163', '216.238.71.13', '147.78.0.165', '89.58.38.4', '54.246.224.74', 
                '194.163.134.104', '45.32.67.144', '185.116.60.232', '95.216.116.209', '147.78.3.161', 
                '95.179.133.28', '200.58.127.145', '104.225.142.116', '193.203.191.189']
               ]

#########################################
#               Unit Test               #
#########################################
class TestAttackGenerator(unittest.TestCase):
    def test_parse_attack_profile(self):
        print("Test parse_attack_profile()")
        attack_profile = parse_attack_profile("test")
        self.assertTrue(attack_profile)
        check = [
            {'tick': 0},
            {'attacks': [{'ICMP flood': {'ratio': [0.0, 0.3], 'rate ratio': 0.3}},
                         {'UDP flood': {'ratio': [0.3, 0.6], 'rate ratio': 0.3}},
                         {'DNS amp': {'ratio': [0.6, 0.9], 'rate ratio': 0.3}},
                         {'Coremelt': {'ratio': [0.9, 1.0], 'rate ratio': 0.1}}]},
            {'tick': 1},
            {'attacks': [{'ICMP flood': {'ratio': [0.0, 0.1], 'rate ratio': 0.1}},
                         {'UDP flood': {'ratio': [0.1, 0.2], 'rate ratio': 0.1}},
                         {'DNS amp': {'ratio': [0.2, 1.0], 'rate ratio': 0.8}}]}
            ]
        self.assertEqual(attack_profile, check)
        for d in attack_profile:
            key = get_key(d)
            if key == "tick":
                print(f"Tick {d['tick']}")
            elif key == "attacks":
                for atk in d["attacks"]:
                    atk_type = get_key(atk)
                    atk_ratio = atk[atk_type]['rate ratio']
                    print(f"\t{atk_type} {atk_ratio}")
            else:
                raise ValueError("Invalid key in attack profile")
        print("======== PASS =========\n")

    def test_generate(self):
        print("Test generate()")
        benign_unique_flowkey = 30000
        attack_unique_ip = 10000
        profile_name = "test"
        volume = 1 # 1Gb traffic
        ag = AttackGenerator(benign_unique_flowkey, attack_unique_ip, profile_name, 0, volume, [], 1, 1, 0)
        for tick in range(ag.max_tick + 1):
            ag.generate(tick)

        total_pkt_volume = 0
        for tick in ag.traffic.keys():
            print(f"Tick {tick}")
            print(f"\tn_pkt = {len(ag.traffic[tick])}")
            for pkt in ag.traffic[tick]:
                total_pkt_volume += pkt.packet_size
        print(f"Total packet volume = {total_pkt_volume} B")

        # Check if packet generated for all ticks
        n_ticks = ag.max_tick + 1
        if total_pkt_volume >= volume * 125 * 1000 * 1000 * n_ticks:
            print("======== PASS =========\n")
        else:
            raise ValueError("Total packet volume is less than 1Gbps*2s")

    def test_generate_all(self):
        print("Test generate_all()")
        benign_unique_flowkey = 30000
        attack_unique_ip = 10000
        profile_name = "test_all"
        volume = 0.5
        ag = AttackGenerator(benign_unique_flowkey, attack_unique_ip, profile_name, 0, volume, [], 1, 1, 0)
        ag.generate_all(1)

        total_pkt_volume = 0
        for tick in ag.traffic.keys():
            print(f"Tick {tick}")
            print(f"\tn_pkt = {len(ag.traffic[tick])}")
            for pkt in ag.traffic[tick]:
                total_pkt_volume += pkt.packet_size
        print(f"Total packet volume = {total_pkt_volume} B")

        # Check if packet generated for all ticks
        n_ticks = ag.max_tick + 1
        if n_ticks != len(ag.traffic.keys()):
            raise Exception("Fail to generate proper attack traffic")
        if total_pkt_volume >= volume * 125 * 1000 * 1000 * n_ticks:
            print("======== PASS =========\n")
        else:
            raise Exception("Total packet volume is less than 0.5Gbps*4s\n")

if __name__ == '__main__':
    unittest.main()
    # print(list(set(quic_servers)))
