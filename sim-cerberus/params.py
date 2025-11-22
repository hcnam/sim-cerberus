#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

class Params:
    def __init__(self, setting: str):
        param_file = f"params/{setting}.json"
        with open(param_file, mode="r") as j_object:
            j_data = json.load(j_object)

        self.task_match_action_table = dict_with_int_key(j_data["task_match_action_table"])
        self.reg_alloc_table = dict_with_int_key(j_data["reg_alloc_table"])
        self.blocklist_size = j_data["blocklist_size"]

        self.shrink_ratio_exp = j_data["shrink_ratio_exp"]  # experiment is shrinked by ratio of 2**self.shrink_ratio_exp
        self.pcap_file = j_data["pcap_file"]
        self.benign_volume = j_data["benign_volume"]    # Gbps
        self.attack_volume = j_data["attack_volume"]    # Gbps
        self.atk_profile = j_data["atk_profile"]
        self.benign_unique_flowkey = j_data["benign_unique_flowkey"]
        self.attack_unique_ip = j_data["attack_unique_ip"]
        self.tick_divisor = j_data["tick_divisor"]
        self.attack_start_subtick = j_data["attack_start_subtick"]      # (1/tick_divisor) second
        self.attack_tick_to_subtick = j_data["attack_tick_to_subtick"]  # (1/tick_divisor) second
        self.refresh_cycle = j_data["refresh_cycle"]    # second
        self.n_hash = j_data["n_hash"]
        self.crc_polynomial_degree = j_data["crc_polynomial_degree"]
        self.seed = j_data["seed"]

        self.elephant_region = j_data["elephant_region"]
        self.elephant_cycle = j_data["elephant_cycle"]  # second

        self.adaptive_memory = j_data["adaptive_memory"]
        self.adaptive_memory_cycle = j_data["adaptive_memory_cycle"]    # second

        self.statistics_cycle_tick = j_data["statistics_cycle_tick"]        # second
        self.statistics_cycle_subtick = j_data["statistics_cycle_subtick"]  # (1/tick_divisor) second
        self.cp_processing_threshold = j_data["cp_processing_threshold"] * 1000 * 1000 * 1000 / 8   # Bps
        self.data_to_control_channel_bandwidth = j_data["data_to_control_channel_bandwidth"] * 1000 * 1000 * 1000 / 8   # Bps
        self.mem_usage = j_data["mem_usage"]

        # shrink experiment by 2**shrink_ratio_exp
        if self.attack_start_subtick < 0:
            raise ValueError(f"Value attack_start_subtick should be nonnegative: {self.attack_start_subtick}")
        if self.shrink_ratio_exp < 0:
            raise ValueError(f"Value shrink_ratio_exp should be nonnegative: {self.shrink_ratio_exp}")
        shrink_ratio = 2**self.shrink_ratio_exp
        for key in self.reg_alloc_table:
            # self.reg_alloc_table[key][1] -= self.shrink_ratio_exp   # dp_counter_size
            # self.reg_alloc_table[key][2] -= self.shrink_ratio_exp   # cp_counter_size
            self.reg_alloc_table[key][3] -= self.shrink_ratio_exp   # array_size
            self.reg_alloc_table[key][4] -= self.shrink_ratio_exp   # elephant_array_size
        self.benign_volume /= shrink_ratio
        self.attack_volume /= shrink_ratio
        self.benign_unique_flowkey = round(self.benign_unique_flowkey / shrink_ratio)
        self.attack_unique_ip = round(self.attack_unique_ip / shrink_ratio)
        self.cp_processing_threshold /= shrink_ratio
        self.data_to_control_channel_bandwidth /= shrink_ratio

    def print(self):
        print(f"TASK_MATCH_ACTION_TABLE:\n {self.task_match_action_table}")
        print(f"REG_ALLOC_TABLE:\n {self.reg_alloc_table}")
        print(f"BLOCKLIST_SIZE: {self.blocklist_size}")

        print(f"SHRINK_RATIO_EXP: {self.shrink_ratio_exp}")
        print(f"PCAP_FILE: {self.pcap_file}")
        print(f"BENIGN_VOLUME: {self.benign_volume} Gbps")
        print(f"ATTACK_VOLUME: {self.attack_volume} Gbps")
        print(f"ATK_PROFILE: {self.atk_profile}")
        print(f"BENIGN_UNIQUE_FLOWKEY: {self.benign_unique_flowkey}")
        print(f"ATTACK_UNIQUE_IP: {self.attack_unique_ip}")
        print(f"TICK_DIVISOR: {self.tick_divisor}")
        print(f"ATTACK START SUBTICK: {self.attack_start_subtick}/{self.tick_divisor} seconds")
        print(f"ATTACK_TICK_TO_SUBTICK: {self.attack_tick_to_subtick}")
        print(f"REFRESH_CYCLE: {self.refresh_cycle} (unit: seconds)")
        print(f"N_HASH: {self.n_hash}")
        print(f"CRC_POLYNOMIAL_DEGREE: {self.crc_polynomial_degree}")
        print(f"SEED: {self.seed}")

        print(f"ELEPHANT_REGION: {self.elephant_region}")
        print(f"ELEPHANT_CYCLE: {self.elephant_cycle} seconds")

        print(f"ADAPTIVE_MEMORY: {self.adaptive_memory}")
        print(f"ADAPTIVE_MEMORY_CYCLE: {self.adaptive_memory_cycle} seconds")

        print(f"STATISTICS_CYCLE_TICK: {self.statistics_cycle_tick} seconds")
        print(f"STATISTICS_CYCLE_SUBTICK: {self.statistics_cycle_subtick}/{self.tick_divisor} seconds")
        print(f"CP_PROCESSING_THRESHOLD: {self.cp_processing_threshold} Bps")
        print(f"DATA_TO_CONTROL_CHANNEL_BANDWIDTH: {self.data_to_control_channel_bandwidth} Bps")
        print(f"MEM_USAGE: {self.mem_usage}")

def dict_with_int_key(d: dict[str]) -> dict[int]:
    tmp = dict()
    for key in d:
        if key.lstrip('-').isdigit():
            value = d[key]
            if isinstance(value, dict):
                value.pop("__comment__", None)
            tmp[int(key)] = value
    return tmp

if __name__ == '__main__':
    params = Params("my3")
    params.print()
