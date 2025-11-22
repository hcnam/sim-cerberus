#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from common import *
from run_sim import defense_dict
import flowkey
from itertools import combinations
import os
import json
import yaml

def make_json(defense_nos: tuple[int], combination_path: str, filename: str):
    fk = flowkey.Flowkey()
    is_bf = [fk.get_flowkey(x)[4] for x in defense_nos]
    dp_counter_size = allocate_slice(32, is_bf)

    task_match_action_table = {}
    task_match_action_table["__comment__"] = ["TASK_ID : {defense_no: 0~15}",
                                              "defense_no can be from 0 to 15 (0 is no defense), refer to Cerberus paper for full detail in numbers",
                                              "Parameters 'condition_key, task_key, action, value, is_bf' can be added for custom CMS update method",
                                              "Parameters 'defense_condition_key, defense_task_key, defense_threshold, if_action, else_action' can be added for custom defense method"
                                             ]
    for i in range(len(defense_nos)):
        task_match_action_table[str(i)] = {"__comment__" : defense_dict[defense_nos[i]],
                                           "defense_no" : defense_nos[i]}
    reg_alloc_table = {}
    reg_alloc_table["__comment__"] = "TASK_ID : [REG_ID, DP_COUNTER_SIZE, CP_COUNTER_SIZE, ARRAY_SIZE, ELEPHANT_ARRAY_SIZE (not used if elephant_region is false)]"
    for i in range(len(defense_nos)):
        reg_alloc_table[str(i)] = [0, dp_counter_size[i], 16, 16, 13]

    comment = ["benign_volume/attack_volume/cp_processing_threshold/data_to_control_channel_bandwidth (Gbps)",
               "refresh_cycle/elephant_cycle/adaptive_memory_cycle/statistics_cycle_tick (seconds)",
               "attack_start_subtick/attack_tick_to_subtick/statistics_cycle_subtick ((1/tick_divisor) seconds)",
               "crc_polynomial_degree can be one of [8, 16, 24, 32, 64] (24 or above is recommended)"
              ]

    path = f"params/{combination_path}"
    if not os.path.exists(path):
        os.makedirs(path)
    with open(f"{path}{filename}.json", "w") as json_file:
        json.dump({"task_match_action_table" : task_match_action_table,
                    "reg_alloc_table" : reg_alloc_table,
                    "blocklist_size": 16,
                    "shrink_ratio_exp": 0,
                    "pcap_file" : "202404251400.pcap",
                    "benign_volume" : 1,
                    "attack_volume" : 10,
                    "atk_profile" : f"{combination_path}{filename}",
                    "benign_unique_flowkey" : 30000,
                    "attack_unique_ip" : 10000,
                    "tick_divisor" : 10,
                    "attack_start_subtick": 0,
                    "attack_tick_to_subtick": 10,
                    "refresh_cycle" : [4] * len(defense_nos),
                    "n_hash" : 4,
                    "crc_polynomial_degree" : 32,
                    "seed" : 1234,
                    "elephant_region" : False,
                    "elephant_cycle" : 1,
                    "adaptive_memory" : True,
                    "adaptive_memory_cycle" : 1,
                    "statistics_cycle_tick" : 1,
                    "statistics_cycle_subtick" : 1,
                    "cp_processing_threshold" : 2,
                    "data_to_control_channel_bandwidth" : 10,
                    "mem_usage" : False,
                    "__comment__": comment}
                    , json_file, indent=4)

def make_yaml(defense_nos: tuple[int], combination_path: str, filename: str):
    result = []
    small_packet = [x for x in defense_nos if x in [12, 13]]
    small_middle_packet = [x for x in defense_nos if x in [1]]
    middle_packet = [x for x in defense_nos if x in [2, 4, 7, 8, 9, 10, 14, 15]]
    big_packet = [x for x in defense_nos if x in [3, 5, 6, 11]]
    attack_order = small_packet + small_middle_packet + middle_packet + big_packet
    i = 0
    while len(attack_order) % 4 != 0:
        if small_packet:
            attack_order.insert(len(small_packet)+i, small_packet[i%len(small_packet)])
        elif small_middle_packet:
            attack_order.insert(len(small_middle_packet)+i, small_middle_packet[i%len(small_middle_packet)])
        elif middle_packet:
            attack_order.insert(len(middle_packet)+i, middle_packet[i%len(middle_packet)])
        else:
            attack_order.insert(len(big_packet)+i, big_packet[i%len(big_packet)])
        i += 1
    for i in range(16):
        result.append({'tick' : i})
        result.append({'attacks' : [{defense_dict[attack_order[i%len(attack_order)]] : {'ratio' : [0.0, 1.0], 'rate ratio': 1.0}}]})

    path = f"atk_profile/{combination_path}"
    if not os.path.exists(path):
        os.makedirs(path)
    with open(f"{path}{filename}.yaml", "w") as yaml_file:
        yaml.dump(result, yaml_file, default_flow_style=False)

def main(n_comb: int, exp_name: str):
    combination_path = f"combination {n_comb} {exp_name}/" if exp_name else f"combination {n_comb}/"
    total_defense = list(range(1, 16))
    for defense_nos in combinations(total_defense, n_comb):
        filename = "_".join([str(x) for x in defense_nos])
        make_json(defense_nos, combination_path, filename)
        make_yaml(defense_nos, combination_path, filename)


if __name__ == '__main__':
    main(1, "no elephant")
