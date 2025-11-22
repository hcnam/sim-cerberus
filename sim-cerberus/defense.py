#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import packet.packet as pkt

class Defense:
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

    # if_action, else_action not used
    def get_defense(self, defense_no: int) -> tuple[list[list], list[str], int, str, str]:   # defense_condition_key, defense_task_key, threshold, if_action, else_action
        return self.defense_dict[defense_no]()

    def no_defense(self) -> tuple[list[list], list[str], int, str, str]:   # rate counter
        return [[None, None, None, None, "ASDF"]], ["src_ip", "dst_ip"], 0, "pass", "pass"

    def icmp_flood(self) -> tuple[list[list], list[str], int, str, str]:
        return [[None, None, None, None, "ICMP"]], ["src_ip", "dst_ip"], 400, "rlimit", "pass"

    def smurf_attack(self) -> tuple[list[list], list[str], int, str, str]:
        return [[None, None, None, None, "ICMP_reply"]], ["dst_ip", "src_ip"], 1, "pass", "drop"

    def coremelt(self) -> tuple[list[list], list[str], int, str, str]:
        return [[None, None, None, None, None]], ["src_ip", "dst_ip"], 46080, "drop", "pass"

    def dns_amplification(self) -> tuple[list[list], list[str], int, str, str]:
        return [[None, pkt.int_to_bytes(53, 2), None, None, None]], ["dst_ip", "dst_port", "src_ip", "src_port"], 1, "pass", "drop"

    def udp_flood(self) -> tuple[list[list], list[str], int, str, str]:
        return [[None, None, None, None, "UDP"]], ["src_ip", "dst_ip"], 400, "rlimit", "pass"

    def dns_flood(self) -> tuple[list[list], list[str], int, str, str]:
        return [[None, None, None, pkt.int_to_bytes(53, 2), None]], ["src_ip", "dst_ip"], 150, "rlimit", "pass"

    def ntp_amplification(self) -> tuple[list[list], list[str], int, str, str]:
        return [[None, pkt.int_to_bytes(123, 2), None, None, None]], ["dst_ip", "dst_port", "src_ip", "src_port"], 1, "pass", "drop"

    def ssdp_amplification(self) -> tuple[list[list], list[str], int, str, str]:
        return [[None, pkt.int_to_bytes(1900, 2), None, None, None]], ["dst_ip", "dst_port", "src_ip", "src_port"], 1, "pass", "drop"

    def memcached_amplification(self) -> tuple[list[list], list[str], int, str, str]:
        return [[None, pkt.int_to_bytes(11211, 2), None, None, None]], ["dst_ip", "dst_port", "src_ip", "src_port"], 1, "pass", "drop"

    def quic_amplification(self) -> tuple[list[list], list[str], int, str, str]:
        return [[None, pkt.int_to_bytes(80, 2), None, None, "UDP"], [None, pkt.int_to_bytes(443, 2), None, None, "UDP"]], ["dst_ip", "dst_port", "src_ip", "src_port"], 1, "pass", "drop"

    def http_flood(self) -> tuple[list[list], list[str], int, str, str]:
        return [[None, None, None, pkt.int_to_bytes(80, 2), "TCP"], [None, None, None, pkt.int_to_bytes(443, 2), "TCP"]], ["src_ip", "dst_ip"], 150, "puzzle", "pass"

    def slowloris(self) -> tuple[list[list], list[str], int, str, str]:
        return [[None, None, None, pkt.int_to_bytes(80, 2), "TCP_SYN"], [None, None, None, pkt.int_to_bytes(443, 2), "TCP_SYN"]], ["src_ip", "dst_ip"], 400, "drop", "pass"

    def syn_flood(self) -> tuple[list[list], list[str], int, str, str]:
        return [[None, None, None, None, "TCP_SYN"]], ["src_ip", "dst_ip"], 400, "drop", "pass"

    def ack_flood(self) -> tuple[list[list], list[str], int, str, str]:
        return [[None, None, None, None, "TCP_ACK"]], ["src_ip", "src_port", "dst_ip", "dst_port", "protocol_byte"], 1, "pass", "drop"

    def rst_fin_flood(self) -> tuple[list[list], list[str], int, str, str]:
        return [[None, None, None, None, "TCP_RST"], [None, None, None, None, "TCP_FIN"]], ["src_ip", "src_port", "dst_ip", "dst_port", "protocol_byte"], 1, "pass", "drop"
