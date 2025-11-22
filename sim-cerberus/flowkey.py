#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import packet.packet as pkt

class Flowkey:
    def __init__(self):
        self.defense_dict = {
            0: self.no_defense,
            1: self.icmp_flood,
            2: self.smurf_attack,
            3: self.coremelt,
            4: self.dns_amplification,
            5: self.udp_flood,
            6: self.dns_flood,
            7: self.ntp_amplification,
            8: self.ssdp_amplification,
            9: self.memcached_amplification,
            10: self.quic_amplification,
            11: self.http_flood,
            12: self.slowloris,
            13: self.syn_flood,
            14: self.ack_flood,
            15: self.rst_fin_flood
        }

    def get_flowkey(self, defense_no: int) -> tuple[list[list], list[str], list[str], int, bool]: # condition_key, task_key, action, value, is_bf
        return self.defense_dict[defense_no]()

    def no_defense(self) -> tuple[list[list], list[str], list[str], int, bool]: # rate counter
        return [[None, None, None, None, None]], ["src_ip", "dst_ip"], ["plus"], 1, False

    def icmp_flood(self) -> tuple[list[list], list[str], list[str], int, bool]:
        return [[None, None, None, None, "ICMP"]], ["src_ip", "dst_ip"], ["plus"], 1, False

    def smurf_attack(self) -> tuple[list[list], list[str], list[str], int, bool]:
        return [[None, None, None, None, "ICMP_request"]], ["src_ip", "dst_ip"], ["setbitFalse"], 1, True

    def coremelt(self) -> tuple[list[list], list[str], list[str], int, bool]:
        return [[None, None, None, None, None]], ["src_ip", "dst_ip"], ["plus"], 0, False

    def dns_amplification(self) -> tuple[list[list], list[str], list[str], int, bool]:
        return [[None, None, None, pkt.int_to_bytes(53, 2), None]], ["src_ip", "src_port", "dst_ip", "dst_port"], ["setbitFalse"], 1, True

    def udp_flood(self) -> tuple[list[list], list[str], list[str], int, bool]:
        return [[None, None, None, None, "UDP"]], ["src_ip", "dst_ip"], ["plus"], 1, False

    def dns_flood(self) -> tuple[list[list], list[str], list[str], int, bool]:
        return [[None, None, None, pkt.int_to_bytes(53, 2), None]], ["src_ip", "dst_ip"], ["plus"], 1, False

    def ntp_amplification(self) -> tuple[list[list], list[str], list[str], int, bool]:
        return [[None, None, None, pkt.int_to_bytes(123, 2), None]], ["src_ip", "src_port", "dst_ip", "dst_port"], ["setbitFalse"], 1, True

    def ssdp_amplification(self) -> tuple[list[list], list[str], list[str], int, bool]:
        return [[None, None, None, pkt.int_to_bytes(1900, 2), None]], ["src_ip", "src_port", "dst_ip", "dst_port"], ["setbitFalse"], 1, True

    def memcached_amplification(self) -> tuple[list[list], list[str], list[str], int, bool]:
        return [[None, None, None, pkt.int_to_bytes(11211, 2), None]], ["src_ip", "src_port", "dst_ip", "dst_port"], ["setbitFalse"], 1, True

    def quic_amplification(self) -> tuple[list[list], list[str], list[str], int, bool]:
        return [[None, None, None, pkt.int_to_bytes(80, 2), "UDP"], [None, None, None, pkt.int_to_bytes(443, 2), "UDP"]], ["src_ip", "src_port", "dst_ip", "dst_port"], ["setbitFalse"], 1, True

    def http_flood(self) -> tuple[list[list], list[str], list[str], int, bool]:
        return [[None, None, None, pkt.int_to_bytes(80, 2), "TCP"], [None, None, None, pkt.int_to_bytes(443, 2), "TCP"]], ["src_ip", "dst_ip"], ["plus"], 1, False

    def slowloris(self) -> tuple[list[list], list[str], list[str], int, bool]:  # 공격 이상함
        return [[None, None, None, pkt.int_to_bytes(80, 2), "TCP_SYN"], [None, None, None, pkt.int_to_bytes(443, 2), "TCP_SYN"]], ["src_ip", "dst_ip"], ["plus"], 1, False

    def syn_flood(self) -> tuple[list[list], list[str], list[str], int, bool]:
        return [[None, None, None, None, "TCP_SYN"]], ["src_ip", "dst_ip"], ["plus"], 1, False

    def ack_flood(self) -> tuple[list[list], list[str], list[str], int, bool]:
        return [[None, None, None, None, "TCP_SYN"]], ["src_ip", "src_port", "dst_ip", "dst_port", "protocol_byte"], ["setbitFalse"], 1, True

    def rst_fin_flood(self) -> tuple[list[list], list[str], list[str], int, bool]:
        return [[None, None, None, None, "TCP_SYN"]], ["src_ip", "src_port", "dst_ip", "dst_port", "protocol_byte"], ["setbitFalse"], 1, True
