#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import cerberus
from packet import attack_generator as gen
import save_results
import defense
import flowkey
import params
from common import *
import numpy as np
from datetime import datetime
import time
from tqdm import tqdm
import random
import sys
# import tracemalloc

defense_dict = {
    -1: "Pcap",
    0:  "Benign",
    1:  "ICMP flood",
    2:  "Smurf attack",
    3:  "Coremelt",
    4:  "DNS amp",
    5:  "UDP flood",
    6:  "DNS flood",
    7:  "NTP amp",
    8:  "SSDP amp",
    9:  "Memcached amp",
    10: "QUIC amp",
    11: "HTTP flood",
    12: "Slowloris",
    13: "SYN flood",
    14: "ACK flood",
    15: "RST FIN flood"
}

def update_true_value(task_id: int, operation: str, flow_key, amount: int, true_value: list[dict]):
    if operation == "plus":
        if flow_key in true_value[task_id]:
            true_value[task_id][flow_key] += amount
        else:
            true_value[task_id][flow_key] = amount
    elif operation == "minus":
        if flow_key in true_value[task_id]:
            true_value[task_id][flow_key] -= amount
        else:
            true_value[task_id][flow_key] = -amount
    elif operation == "setbitTrue":
        if flow_key in true_value[task_id]:
            true_value[task_id][flow_key] |= amount
        else:
            true_value[task_id][flow_key] = amount
    elif operation == "setbitFalse":
        true_value[task_id][flow_key] = amount
    else:
        raise ValueError(f"Incorrect operation: {operation}")

def relative_error_cerb(cerb: cerberus.Cerberus, true_value: list[dict], task_id: int) -> list[int]:
    re = []
    for flow_key in true_value[task_id]:
        read_value = cerb.read(task_id, flow_key)
        if true_value[task_id][flow_key] != 0:
            re.append(min(abs(read_value - true_value[task_id][flow_key]) / true_value[task_id][flow_key], 1))
        elif read_value == 0:
            re.append(0)
        else:
            re.append(1)
    count, _ = np.histogram(re, bins=1000, range=(0, 1))
    return count.tolist()

def main(param_filename: str, exp_name: str):
    task_per_reg = []
    slice_per_registers = []
    cp_slice_per_tasks = []
    elephant_array_sizes = []
    array_size_per_registers = []
    n_register = 0
    re_cerb = {}
    param = params.Params(param_filename)
    if param.mem_usage:
        tracemalloc.start()
    mem_usage = {x: [] for x in ["Total", "Cerberus", "True_value", "Traffic"]}
    fpr = []
    fnr = []
    for task_id in sorted(param.reg_alloc_table):
        reg_id, dp_counter_size, cp_counter_size, array_size, elephant_array_size = param.reg_alloc_table[task_id]
        if n_register <= reg_id:
            task_per_reg.append([])
            slice_per_registers.append([])
            array_size_per_registers.append([])
            elephant_array_sizes.append([])
            n_register += 1
        task_per_reg[reg_id].append(task_id)
        slice_per_registers[reg_id].append(dp_counter_size)
        cp_slice_per_tasks.append(cp_counter_size)
        array_size_per_registers[reg_id].append(array_size)
        elephant_array_sizes[reg_id].append(elephant_array_size)
        re_cerb[task_id] = [0] * 1000   # count
    if not param.elephant_region:
        elephant_array_sizes = [[] for _ in range(n_register)]
    refresh_cycle_per_attack = {defense_dict[param.task_match_action_table[i]['defense_no']]: param.refresh_cycle[i] for i in param.task_match_action_table}

    df = defense.Defense()
    defense_table = {task_id: df.get_defense(param.task_match_action_table[task_id]["defense_no"]) if "defense_condition_key" not in param.task_match_action_table[task_id]
                     else [param.task_match_action_table[task_id]["defense_condition_key"], param.task_match_action_table[task_id]["defense_task_key"], param.task_match_action_table[task_id]["defense_threshold"], param.task_match_action_table[task_id]["if_action"], param.task_match_action_table[task_id]["else_action"]]
                     for task_id in param.task_match_action_table}
    fk = flowkey.Flowkey()
    flowkey_table = {task_id: fk.get_flowkey(param.task_match_action_table[task_id]["defense_no"]) if "condition_key" not in param.task_match_action_table[task_id]
                     else [param.task_match_action_table[task_id]["condition_key"], param.task_match_action_table[task_id]["task_key"], param.task_match_action_table[task_id]["action"], param.task_match_action_table[task_id]["value"], param.task_match_action_table[task_id]["is_bf"]]
                     for task_id in param.task_match_action_table}

    cerb = cerberus.Cerberus(task_per_reg, slice_per_registers, cp_slice_per_tasks, array_size_per_registers, elephant_array_sizes, n_register, flowkey_table, defense_table, param)
    true_value = [{} for _ in range(len(cp_slice_per_tasks))]
    # PCAP_FILE not used
    random.seed(param.seed)
    generator = gen.AttackGenerator(param.benign_unique_flowkey, param.attack_unique_ip, param.atk_profile, param.benign_volume, param.attack_volume, refresh_cycle_per_attack, param.tick_divisor, param.attack_tick_to_subtick, param.attack_start_subtick)
    true_positive = 0   # blocked malicious
    false_positive = 0  # blocked benign
    false_negative = 0  # unblocked malicious
    true_negative = 0   # unblocked benign
    rate = {atk: [] for atk in generator.attack_str_key + ["Attack total", "Benign"]}

    epoch = [0] * len(sum(task_per_reg, []))
    current_window = [0] * len(sum(task_per_reg, []))

    num_tick = ((generator.max_tick+1)*param.attack_tick_to_subtick + param.attack_start_subtick - 1)//param.tick_divisor + 1
    expected_attack_total_bytes = sum([sum(generator.rate[atk]) for atk in generator.rate]) \
                                + sum([sum([sum([x*y for x, y in zip(generator.seq_size[atk][i], generator.seq_count[atk][i])])
                                            * sum(generator.seq_ratio[atk][i][2*j+1] - generator.seq_ratio[atk][i][2*j] for j in range(len(generator.seq_ratio[atk][i])//2))
                                            for i in range(len(generator.seq_size[atk]))]) for atk in generator.seq_size]) * param.attack_unique_ip \
                                + sum([sum(generator.loop_rate[atk]) for atk in generator.loop_rate])
    benign_total_bytes = param.benign_volume*num_tick * 125 * 1000 * 1000
    total_length = round(expected_attack_total_bytes + benign_total_bytes)
    pbar = tqdm(total=total_length)

    random.seed(param.seed)
    for tick in range(num_tick):
        for subtick in range(param.tick_divisor):
            current_subtick = tick * param.tick_divisor + subtick
            generator.generate(current_subtick)
            for atk in rate:
                rate[atk].append(0)

            for p in generator.traffic[current_subtick]:
                # update CMS and blocklist, and block
                blocked = cerb.update(p)
                for task_id in sorted(param.task_match_action_table):
                    condition_key, task_key, task_action, task_value, _ = flowkey_table[task_id]
                    condition, flow_key = cerberus.find_flowkey(condition_key, task_key, p)
                    if (condition):
                        amount = p.packet_size if task_value == 0 else task_value
                        for operation in task_action:
                            update_true_value(task_id, operation, flow_key, amount, true_value)

                # accumulate whether blocking was successful
                if any(blocked):
                    if 1 <= p.attack_type <= 15:
                        true_positive += 1
                    else:
                        false_positive += 1
                else:
                    if 1 <= p.attack_type <= 15:
                        false_negative += 1
                    else:
                        true_negative += 1

                rate[defense_dict[p.attack_type]][current_subtick] += p.packet_size / 125 / 1000 / 1000 / (param.statistics_cycle_subtick/param.tick_divisor)
                if 1 <= p.attack_type <= 15:
                    rate["Attack total"][current_subtick] += p.packet_size / 125 / 1000 / 1000 / (param.statistics_cycle_subtick/param.tick_divisor)
                pbar.update(p.packet_size)

            cerb.update_subtick(current_subtick)
            if param.mem_usage:
                current, peak = tracemalloc.get_traced_memory()
                mem_usage["Total"].append(current / 1000 / 1000)
                mem_usage["Cerberus"].append(getsize(cerb) / 1000 / 1000)
                mem_usage["True_value"].append(getsize(true_value) / 1000 / 1000)
                mem_usage["Traffic"].append(getsize(generator.traffic) / 1000 / 1000)
            generator.delete_traffic(current_subtick)

            # evaluate fpr, fnr
            if true_negative + false_positive != 0:
                fpr.append(false_positive / (true_negative + false_positive) * 100)
            else:
                fpr.append(0)
            if true_positive + false_negative != 0:
                fnr.append(false_negative / (true_positive + false_negative) * 100)
            else:
                fnr.append(0)
            true_positive = 0
            false_positive = 0
            false_negative = 0
            true_negative = 0

        # evaluate relative error when window changes
        cerb.update_tick(tick)
        for task_id in sum(task_per_reg, []):
            if current_window[task_id] != cerb.current_window[task_id]:
                current_window[task_id] = cerb.current_window[task_id]
                re_cerb[task_id] = list_elementwise_add(re_cerb[task_id], relative_error_cerb(cerb, true_value, task_id))
                # print(f"Task {task_id}\tEpoch {epoch[task_id]} finished: {len(true_value[task_id])}", flush=True)   # number of distinct flowkeys
                print(f"Task {task_id}\tEpoch {epoch[task_id]} finished", flush=True)
                true_value[task_id].clear()
                epoch[task_id] += 1

    filename = f"results/{param_filename} {exp_name} {str(datetime.now()).replace(':', ';')}"
    relative_error, fpr_info, fnr_info, counter_size, uploaded_packet, uploaded_packet_ratio, rate_info, cp_not_processed, mem_usage_info, bandwidth_utilization, overflowed_packet_ratio, cp_max_info \
                 = save_results.draw_statistics(cerb, param, param_filename, filename, len(param.task_match_action_table), defense_dict, re_cerb, fpr, fnr, rate, mem_usage)
    maxbits_used = save_results.draw_cp_max_bits(cerb, param, param_filename, filename, defense_dict)

    # save results into json
    save_results.save_results(param_filename, filename, relative_error, fpr_info, fnr_info, counter_size, uploaded_packet, uploaded_packet_ratio, rate_info, cp_not_processed, mem_usage_info, bandwidth_utilization, overflowed_packet_ratio, maxbits_used, cp_max_info)
    # save params into json
    save_results.save_params(param, filename)
    # save attack profile into yaml
    save_results.save_attack_profile(generator, param, filename)

    print(f"Results are saved at {filename}", flush=True)

if __name__ == '__main__':
    param_filename = "1_5_11_13"
    exp_name = "best new 195"
    if len(sys.argv) >= 3:
        param_filename = sys.argv[1]
        exp_name = " ".join(sys.argv[2:])

    print(f"Started experiment {param_filename} {exp_name} at {datetime.now()}", flush=True)
    start_time = time.time()
    main(param_filename, exp_name)
    elapsed_time = time.time() - start_time
    hours, rem = divmod(elapsed_time, 3600)
    minutes, seconds = divmod(rem, 60)
    print(f"Execution time: {int(hours):02}:{int(minutes):02}:{seconds:05.2f}", flush=True)
    print(f"Finished experiment {param_filename} {exp_name} at {datetime.now()}", flush=True)
