#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import cerberus
from packet import attack_generator as gen
import params
from common import *
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import math
import json
import yaml

color = ['#1f77b4', '#ff7f0e', '#2ca02c', '#9467bd', '#8c564b', '#e377c2', '#7f7f7f', '#17becf']
benign_color = '#bcbd22'
global_color = '#d62728'

def calc_cdf(count: list[int]):
    count = np.array(count)
    pdf = count / sum(count)    # sum(count) is nonzero
    cdf = np.cumsum(pdf)
    return cdf.tolist()

def evaluate(count: list[int], defense: str, ax, plt_color: str):
    if (sum(count) != 0):
        cdf = calc_cdf(count)
        bins_count = np.arange(0, 1 + 1/1000, 1/1000).tolist()
        ax.plot(bins_count[1:], cdf, label=defense, color=plt_color)
        return bins_count[1:], cdf, defense, plt_color
    else:
        return None

def draw_statistics(cerb: cerberus.Cerberus, param: params.Params, param_filename: str, filename: str, global_index: int, defense_dict, re_cerb, fpr, fnr, rate, mem_usage):
    fig, axes = plt.subplots(ncols=3, nrows=3, figsize=(12, 12))
    axs = axes.ravel()
    axs_index = 0
    task_defense = [(task_id, param.task_match_action_table[task_id]["defense_no"]) for task_id in param.task_match_action_table]
    task_defense = sorted(task_defense, key=lambda x: x[1])
    task_color = {}
    color_index = 0
    for task_id, _ in task_defense:
        task_color[task_id] = color[color_index % len(color)]
        color_index += 1

    relative_error = {}
    axs[axs_index].set_xlabel('Relative error')
    axs[axs_index].set_ylabel('CDF')
    for task_id in sorted(param.task_match_action_table):
        result = evaluate(re_cerb[task_id], defense_dict[param.task_match_action_table[task_id]["defense_no"]], axs[axs_index], task_color[task_id])
        if result:
            relative_error[task_id] = result
    relative_error['xlabel'] = 'Relative error'
    relative_error['ylabel'] = 'CDF'
    relative_error['legend'] = True
    axs[axs_index].legend()
    axs_index += 1

    fpr_info = {}
    axs[axs_index].set_xlabel('Time (second)')
    axs[axs_index].set_ylabel('FPR (%)')
    axs[axs_index].plot(np.arange(0, len(fpr)/param.tick_divisor, 1/param.tick_divisor).tolist(), fpr, color=global_color)
    fpr_info[0] = np.arange(0, len(fpr)/param.tick_divisor, 1/param.tick_divisor).tolist(), fpr, global_color
    fpr_info['max_y'] = 100
    fpr_info['min_y'] = 0
    margin = (fpr_info['max_y']-fpr_info['min_y']) * 0.05
    ymin, ymax = fpr_info['min_y']-margin, fpr_info['max_y']+margin
    axs[axs_index].set_ylim([ymin, ymax])
    fpr_info['xlabel'] = 'Time (second)'
    fpr_info['ylabel'] = 'FPR (%)'
    fpr_info['legend'] = False
    axs_index += 1

    fnr_info = {}
    axs[axs_index].set_xlabel('Time (second)')
    axs[axs_index].set_ylabel('FNR (%)')
    axs[axs_index].plot(np.arange(0, len(fnr)/param.tick_divisor, 1/param.tick_divisor).tolist(), fnr, color=global_color)
    fnr_info[0] = np.arange(0, len(fnr)/param.tick_divisor, 1/param.tick_divisor).tolist(), fnr, global_color
    fnr_info['max_y'] = 100
    fnr_info['min_y'] = 0
    margin = (fnr_info['max_y']-fnr_info['min_y']) * 0.05
    ymin, ymax = fnr_info['min_y']-margin, fnr_info['max_y']+margin
    axs[axs_index].set_ylim([ymin, ymax])
    fnr_info['xlabel'] = 'Time (second)'
    fnr_info['ylabel'] = 'FNR (%)'
    fnr_info['legend'] = False
    axs_index += 1

    counter_size = {}
    axs[axs_index].set_xlabel('Time (second)')
    axs[axs_index].set_ylabel('Counter size (bits)')
    for task_id in sorted(param.task_match_action_table):
        axs[axs_index].plot(np.arange(0, param.statistics_cycle_tick*len(cerb.counter_size_history[task_id]), param.statistics_cycle_tick).tolist(), cerb.counter_size_history[task_id], label=defense_dict[param.task_match_action_table[task_id]["defense_no"]], color=task_color[task_id])
        counter_size[task_id] = np.arange(0, param.statistics_cycle_tick*len(cerb.counter_size_history[task_id]), param.statistics_cycle_tick).tolist(), cerb.counter_size_history[task_id], defense_dict[param.task_match_action_table[task_id]["defense_no"]], task_color[task_id]
    counter_size['xlabel'] = 'Time (second)'
    counter_size['ylabel'] = 'Counter size (bits)'
    counter_size['legend'] = True
    axs[axs_index].legend()
    axs_index += 1

    uploaded_packet = {}
    axs[axs_index].set_xlabel('Time (second)')
    axs[axs_index].set_ylabel('Uploaded packet (M pps)')
    ymax = float('-inf')
    for task_id in sorted(param.task_match_action_table):
        axs[axs_index].plot(np.arange(0, param.statistics_cycle_subtick/param.tick_divisor*len(cerb.uploaded_packet_history[task_id]), param.statistics_cycle_subtick/param.tick_divisor).tolist(), cerb.uploaded_packet_history[task_id], label=defense_dict[param.task_match_action_table[task_id]["defense_no"]], color=task_color[task_id])
        uploaded_packet[task_id] = np.arange(0, param.statistics_cycle_subtick/param.tick_divisor*len(cerb.uploaded_packet_history[task_id]), param.statistics_cycle_subtick/param.tick_divisor).tolist(), cerb.uploaded_packet_history[task_id], defense_dict[param.task_match_action_table[task_id]["defense_no"]], task_color[task_id]
        ymax = max(ymax, max(cerb.uploaded_packet_history[task_id]))
    axs[axs_index].plot(np.arange(0, param.statistics_cycle_subtick/param.tick_divisor*len(cerb.uploaded_packet_history[global_index]), param.statistics_cycle_subtick/param.tick_divisor).tolist(), cerb.uploaded_packet_history[global_index], label="Global", color=global_color)
    uploaded_packet[global_index] = np.arange(0, param.statistics_cycle_subtick/param.tick_divisor*len(cerb.uploaded_packet_history[global_index]), param.statistics_cycle_subtick/param.tick_divisor).tolist(), cerb.uploaded_packet_history[global_index], "Global", global_color
    ymax = max(ymax, max(cerb.uploaded_packet_history[global_index]))
    uploaded_packet['min_y'] = 0
    margin = (ymax - uploaded_packet['min_y']) * 0.05
    ymin, ymax = uploaded_packet['min_y']-margin, ymax+margin
    if ymin == ymax:
        ymin -= (0.05 + 0.1*0.05)
        ymax += (0.05 + 0.1*0.05)
    axs[axs_index].set_ylim([ymin, ymax])
    uploaded_packet['xlabel'] = 'Time (second)'
    uploaded_packet['ylabel'] = 'Uploaded packet (M pps)'
    uploaded_packet['legend'] = True
    axs[axs_index].legend()
    axs_index += 1

    uploaded_packet_ratio = {}
    axs[axs_index].set_xlabel('Time (second)')
    axs[axs_index].set_ylabel('Uploaded packet (%)')
    ymax = float('-inf')
    for task_id in sorted(param.task_match_action_table):
        axs[axs_index].plot(np.arange(0, param.statistics_cycle_subtick/param.tick_divisor*len(cerb.uploaded_packet_ratio_history[task_id]), param.statistics_cycle_subtick/param.tick_divisor).tolist(), cerb.uploaded_packet_ratio_history[task_id], label=defense_dict[param.task_match_action_table[task_id]["defense_no"]], color=task_color[task_id])
        uploaded_packet_ratio[task_id] = np.arange(0, param.statistics_cycle_subtick/param.tick_divisor*len(cerb.uploaded_packet_ratio_history[task_id]), param.statistics_cycle_subtick/param.tick_divisor).tolist(), cerb.uploaded_packet_ratio_history[task_id], defense_dict[param.task_match_action_table[task_id]["defense_no"]], task_color[task_id]
        ymax = max(ymax, max(cerb.uploaded_packet_ratio_history[task_id]))
    axs[axs_index].plot(np.arange(0, param.statistics_cycle_subtick/param.tick_divisor*len(cerb.uploaded_packet_ratio_history[global_index]), param.statistics_cycle_subtick/param.tick_divisor).tolist(), cerb.uploaded_packet_ratio_history[global_index], label="Global", color=global_color)
    uploaded_packet_ratio[global_index] = np.arange(0, param.statistics_cycle_subtick/param.tick_divisor*len(cerb.uploaded_packet_ratio_history[global_index]), param.statistics_cycle_subtick/param.tick_divisor).tolist(), cerb.uploaded_packet_ratio_history[global_index], "Global", global_color
    ymax = max(ymax, max(cerb.uploaded_packet_ratio_history[global_index]))
    uploaded_packet_ratio['min_y'] = 0
    margin = (ymax - uploaded_packet_ratio['min_y']) * 0.05
    ymin, ymax = uploaded_packet_ratio['min_y']-margin, ymax+margin
    if ymin == ymax:
        ymin -= (0.05 + 0.1*0.05)
        ymax += (0.05 + 0.1*0.05)
    axs[axs_index].set_ylim([ymin, ymax])
    uploaded_packet_ratio['xlabel'] = 'Time (second)'
    uploaded_packet_ratio['ylabel'] = 'Uploaded packet (%)'
    uploaded_packet_ratio['legend'] = True
    axs[axs_index].legend()
    axs_index += 1

    rate_info = {}
    axs[axs_index].set_xlabel('Time (second)')
    axs[axs_index].set_ylabel('Rate (Gbps)')
    i = 0
    ymax = float('-inf')
    for atk in rate:
        if atk == "Attack total":
            plt_color = global_color
        else:
            defense_no = get_key_from_value(defense_dict, atk)
            task_id = get_first_from_second(task_defense, defense_no)
            if defense_no == 0:
                plt_color = benign_color
            elif isinstance(task_id, int):
                plt_color = task_color[task_id]
            else:
                plt_color = 'k'
        axs[axs_index].plot(np.arange(0, param.statistics_cycle_subtick/param.tick_divisor*len(rate[atk]), param.statistics_cycle_subtick/param.tick_divisor).tolist(), rate[atk], label=atk, color=plt_color)
        rate_info[i] = np.arange(0, param.statistics_cycle_subtick/param.tick_divisor*len(rate[atk]), param.statistics_cycle_subtick/param.tick_divisor).tolist(), rate[atk], atk, plt_color
        ymax = max(ymax, max(rate[atk]))
        i += 1
    rate_info['min_y'] = 0
    margin = (ymax - rate_info['min_y']) * 0.05
    ymin, ymax = rate_info['min_y']-margin, ymax+margin
    if ymin == ymax:
        ymin -= (0.05 + 0.1*0.05)
        ymax += (0.05 + 0.1*0.05)
    axs[axs_index].set_ylim([ymin, ymax])
    rate_info['xlabel'] = 'Time (second)'
    rate_info['ylabel'] = 'Rate (Gbps)'
    rate_info['legend'] = True
    axs[axs_index].legend()
    axs_index += 1

    cp_not_processed = {}
    axs[axs_index].set_xlabel('Time (second)')
    axs[axs_index].set_ylabel('Packets not processed by CP (%)')
    axs[axs_index].plot(np.arange(0, param.statistics_cycle_subtick/param.tick_divisor*len(cerb.cp_not_processed_packet_history), param.statistics_cycle_subtick/param.tick_divisor).tolist(), cerb.cp_not_processed_packet_history, color=global_color)
    cp_not_processed[0] = np.arange(0, param.statistics_cycle_subtick/param.tick_divisor*len(cerb.cp_not_processed_packet_history), param.statistics_cycle_subtick/param.tick_divisor).tolist(), cerb.cp_not_processed_packet_history, global_color
    ymax = max(cerb.cp_not_processed_packet_history)
    cp_not_processed['min_y'] = 0
    margin = (ymax - cp_not_processed['min_y']) * 0.05
    ymin, ymax = cp_not_processed['min_y']-margin, ymax+margin
    if ymin == ymax:
        ymin -= (0.05 + 0.1*0.05)
        ymax += (0.05 + 0.1*0.05)
    axs[axs_index].set_ylim([ymin, ymax])
    cp_not_processed['xlabel'] = 'Time (second)'
    cp_not_processed['ylabel'] = 'Packets not processed by CP (%)'
    cp_not_processed['legend'] = False
    axs_index += 1

    mem_usage_info = {}
    bandwidth_utilization = {}
    if param.mem_usage:
        axs[axs_index].set_xlabel('Time (second)')
        axs[axs_index].set_ylabel('Mem usage (MB)')
        i = 0
        ymax = float('-inf')
        for x in mem_usage:
            axs[axs_index].plot(np.arange(0, param.statistics_cycle_subtick/param.tick_divisor*len(mem_usage[x]), param.statistics_cycle_subtick/param.tick_divisor).tolist(), mem_usage[x], label=x, color=color[(len(task_color)+i) % len(color)])
            mem_usage_info[i] = np.arange(0, param.statistics_cycle_subtick/param.tick_divisor*len(mem_usage[x]), param.statistics_cycle_subtick/param.tick_divisor).tolist(), mem_usage[x], x, color[(len(task_color)+i) % len(color)]
            ymax = max(ymax, max(mem_usage[x]))
            i += 1
        mem_usage_info['min_y'] = 0
        margin = (ymax - mem_usage_info['min_y']) * 0.05
        ymin, ymax = mem_usage_info['min_y']-margin, ymax+margin
        if ymin == ymax:
            ymin -= (0.05 + 0.1*0.05)
            ymax += (0.05 + 0.1*0.05)
        axs[axs_index].set_ylim([ymin, ymax])
        mem_usage_info['xlabel'] = 'Time (second)'
        mem_usage_info['ylabel'] = 'Mem usage (MB)'
        mem_usage_info['legend'] = True
        axs[axs_index].legend()
        axs_index += 1

        bandwidth_utilization[0] = np.arange(0, param.statistics_cycle_subtick/param.tick_divisor*(len(cerb.bandwidth_utilization_history)), param.statistics_cycle_subtick/param.tick_divisor).tolist(), cerb.bandwidth_utilization_history, global_color
        bandwidth_utilization['xlabel'] = 'Time (second)'
        bandwidth_utilization['ylabel'] = 'Bandwidth utilization (%)'
        bandwidth_utilization['legend'] = False
    else:
        axs[axs_index].set_xlabel('Time (second)')
        axs[axs_index].set_ylabel('Bandwidth utilization (%)')
        axs[axs_index].plot(np.arange(0, param.statistics_cycle_subtick/param.tick_divisor*(len(cerb.bandwidth_utilization_history)), param.statistics_cycle_subtick/param.tick_divisor).tolist(), cerb.bandwidth_utilization_history, color=global_color)
        bandwidth_utilization[0] = np.arange(0, param.statistics_cycle_subtick/param.tick_divisor*(len(cerb.bandwidth_utilization_history)), param.statistics_cycle_subtick/param.tick_divisor).tolist(), cerb.bandwidth_utilization_history, global_color
        ymax = max(cerb.bandwidth_utilization_history)
        bandwidth_utilization['min_y'] = 0
        margin = (ymax - bandwidth_utilization['min_y']) * 0.05
        ymin, ymax = bandwidth_utilization['min_y']-margin, ymax+margin
        if ymin == ymax:
            ymin -= (0.05 + 0.1*0.05)
            ymax += (0.05 + 0.1*0.05)
        axs[axs_index].set_ylim([ymin, ymax])
        bandwidth_utilization['xlabel'] = 'Time (second)'
        bandwidth_utilization['ylabel'] = 'Bandwidth utilization (%)'
        bandwidth_utilization['legend'] = False
        axs_index += 1

    overflowed_packet_ratio = {}
    for task_id in sorted(param.task_match_action_table):
        overflowed_packet_ratio[task_id] = np.arange(0, param.statistics_cycle_subtick/param.tick_divisor*len(cerb.overflowed_packet_ratio_history[task_id]), param.statistics_cycle_subtick/param.tick_divisor).tolist(), cerb.overflowed_packet_ratio_history[task_id], defense_dict[param.task_match_action_table[task_id]["defense_no"]], task_color[task_id]
    overflowed_packet_ratio[global_index] = np.arange(0, param.statistics_cycle_subtick/param.tick_divisor*len(cerb.overflowed_packet_ratio_history[global_index]), param.statistics_cycle_subtick/param.tick_divisor).tolist(), cerb.overflowed_packet_ratio_history[global_index], "Global", global_color
    overflowed_packet_ratio['xlabel'] = 'Time (second)'
    overflowed_packet_ratio['ylabel'] = 'Overflowed packet (%)'
    overflowed_packet_ratio['legend'] = True

    cp_max_info = {}
    for task_id in sorted(param.task_match_action_table):
        cp_max_info[task_id] = np.arange(0, param.statistics_cycle_tick*len(cerb.cp_max_history[task_id]), param.statistics_cycle_tick).tolist(), cerb.cp_max_history[task_id], defense_dict[param.task_match_action_table[task_id]["defense_no"]], task_color[task_id]

    fig.tight_layout()
    # fig.suptitle(f"{param_filename} {exp_name}", y=1.02, fontsize='xx-large')
    fig.savefig(f"{filename}.png", bbox_inches='tight')
    return relative_error, fpr_info, fnr_info, counter_size, uploaded_packet, uploaded_packet_ratio, rate_info, cp_not_processed, mem_usage_info, bandwidth_utilization, overflowed_packet_ratio, cp_max_info

def draw_cp_max_bits(cerb: cerberus.Cerberus, param: params.Params, param_filename: str, filename: str, defense_dict):
    maxbits_used = {0: []}
    for task_id in sorted(param.task_match_action_table):
        for stats_tick in range(len(cerb.cp_max_bits_history[task_id])):
            maxbits_used[0].append([task_id, stats_tick*param.statistics_cycle_tick, cerb.cp_max_bits_history[task_id][stats_tick], cerb.counter_size_history[task_id][stats_tick]])
    df = pd.DataFrame(columns=['Task', 'Tick', 'CP bits', 'DP bits'], data=maxbits_used[0])
    df.set_index(['Task', 'Tick'], inplace=True)
    df0 = df.reorder_levels(['Tick', 'Task']).sort_index()
    colors = plt.cm.Paired.colors
    df0 = df0.unstack(level=-1)
    fig, ax = plt.subplots()
    ax.set_xlabel('Time (second)')
    ax.set_ylabel('Maximum bits used')
    (df0['CP bits'] + df0['DP bits']).plot(kind='bar', color=[colors[2*i] for i in sorted(param.task_match_action_table)], rot=0, ax=ax)
    df0['DP bits'].plot(kind='bar', color=[colors[2*i+1] for i in sorted(param.task_match_action_table)], rot=0, ax=ax)
    handles, _ = plt.gca().get_legend_handles_labels()
    n = len(handles) // 2
    order = [i//2 + (i%2)*n for i in range(2*n)]
    prop = {'size': 32/n} if n >= 4 else None
    legend_labels = [f"{val} ({defense_dict[param.task_match_action_table[task_id]['defense_no']]})" for val, task_id in df0.columns]
    ax.legend([handles[idx] for idx in order],[legend_labels[idx] for idx in order], loc='upper center', bbox_to_anchor=(0.5, -0.05), fancybox=True, shadow=True, ncol=n, prop=prop)
    maxbits_used['xlabel'] = 'Time (second)'
    maxbits_used['ylabel'] = 'Maximum bits used'
    maxbits_used['legend'] = True
    maxbits_used['legend_labels'] = legend_labels
    maxbits_used['tasks'] = len(param.task_match_action_table)
    plt.tight_layout()
    # fig.suptitle(f"{param_filename} {exp_name}", y=1.02, fontsize='x-large')
    plt.savefig(f"{filename} max bits.png", bbox_inches='tight')
    return maxbits_used

def save_results(param_filename: str, filename: str, relative_error, fpr_info, fnr_info, counter_size, uploaded_packet, uploaded_packet_ratio, rate_info, cp_not_processed, mem_usage_info, bandwidth_utilization, overflowed_packet_ratio, maxbits_used, cp_max_info):
    with open(f"{filename}.json", "w") as json_file:
        json.dump({"relative_error" : relative_error,
                   "fpr_info" : fpr_info,
                   "fnr_info" : fnr_info,
                   "counter_size" : counter_size,
                   "uploaded_packet" : uploaded_packet,
                   "uploaded_packet_ratio" : uploaded_packet_ratio,
                   "rate" : rate_info,
                   "cp_not_processed" : cp_not_processed,
                   "mem_usage_info" : mem_usage_info,
                   "bandwidth_utilization" : bandwidth_utilization,
                   "overflowed_packet_ratio" : overflowed_packet_ratio,
                   "maxbits_used" : maxbits_used,
                   "cp_max_info" : cp_max_info,
                   "setting" : param_filename}
                   , json_file, indent=4)

def save_params(param: params.Params, filename: str):
    with open(f"{filename} params.json", "w") as json_file:
        json.dump({"task_match_action_table" : param.task_match_action_table,
                   "reg_alloc_table" : param.reg_alloc_table,
                   "blocklist_size" : param.blocklist_size,
                   "shrink_ratio_exp": 0,
                   "pcap_file" : param.pcap_file,
                   "benign_volume" : param.benign_volume,
                   "attack_volume" : param.attack_volume,
                   "atk_profile" : param.atk_profile,
                   "benign_unique_flowkey" : param.benign_unique_flowkey,
                   "attack_unique_ip" : param.attack_unique_ip,
                   "tick_divisor" : param.tick_divisor,
                   "refresh_cycle" : param.refresh_cycle,
                   "n_hash" : param.n_hash,
                   "crc_polynomial_degree" : param.crc_polynomial_degree,
                   "seed" : param.seed,
                   "elephant_region" : param.elephant_region,
                   "elephant_cycle" : param.elephant_cycle,
                   "adaptive_memory" : param.adaptive_memory,
                   "adaptive_memory_cycle" : param.adaptive_memory_cycle,
                   "statistics_cycle_tick" : param.statistics_cycle_tick,
                   "statistics_cycle_subtick" : param.statistics_cycle_subtick,
                   "cp_processing_threshold" : param.cp_processing_threshold*8/1000/1000/1000,
                   "data_to_control_channel_bandwidth" : param.data_to_control_channel_bandwidth*8/1000/1000/1000}
                   , json_file, indent=4)

def save_attack_profile(generator: gen.AttackGenerator, param: params.Params, filename: str):
    atk_profile = []
    for tick in range(generator.max_tick + 1):
        start_tick = tick*param.attack_tick_to_subtick + param.attack_start_subtick
        end_tick = (tick+1)*param.attack_tick_to_subtick + param.attack_start_subtick
        ratio = []
        for atk in generator.attack_key:
            atk_info = {}
            atk_ratio = generator.ratio[atk][start_tick: end_tick]
            atk_rate = generator.rate[atk][start_tick: end_tick]
            if any(any(not math.isclose(l[2*i], l[2*i+1], abs_tol=1e-07) for i in range(len(l)//2)) for l in atk_ratio) and any(atk_rate):
                if all(x == atk_ratio[0] for x in atk_ratio):
                    atk_info['ratio'] = atk_ratio[0]
                else:
                    atk_info['ratio'] = atk_ratio
                if all(x == atk_rate[0] for x in atk_rate):
                    atk_info['rate ratio'] = atk_rate[0] / param.attack_volume / 125 / 1000 / 1000 * param.attack_tick_to_subtick
                else:
                    atk_info['rate ratio'] = [x / param.attack_volume / 125 / 1000 / 1000 * param.attack_tick_to_subtick for x in atk_rate]
            atk_seq_size = generator.seq_size[atk][start_tick: end_tick]
            atk_seq_count = generator.seq_count[atk][start_tick: end_tick]
            atk_seq_ratio = generator.seq_ratio[atk][start_tick: end_tick]
            if any(any(l) for l in atk_seq_count) and any(any(not math.isclose(l[2*i], l[2*i+1], abs_tol=1e-07) for i in range(len(l)//2)) for l in atk_seq_ratio):
                if all(x == atk_seq_size[0] for x in atk_seq_size):
                    atk_info['seq size'] = atk_seq_size[0]
                else:
                    atk_info['seq size'] = atk_seq_size
                if all(x == atk_seq_count[0] for x in atk_seq_count):
                    atk_info['seq count'] = atk_seq_count[0]
                else:
                    atk_info['seq count'] = atk_seq_count
                if all(x == atk_seq_ratio[0] for x in atk_seq_ratio):
                    atk_info['seq ratio'] = atk_seq_ratio[0]
                else:
                    atk_info['seq ratio'] = atk_seq_ratio
            atk_loop_size = generator.loop_size[atk][start_tick: end_tick]
            atk_loop_count = generator.loop_count[atk][start_tick: end_tick]
            atk_loop_ratio = generator.loop_ratio[atk][start_tick: end_tick]
            atk_loop_rate = generator.loop_rate[atk][start_tick: end_tick]
            if any(any(l) for l in atk_loop_count) and any(any(not math.isclose(l[2*i], l[2*i+1], abs_tol=1e-07) for i in range(len(l)//2)) for l in atk_loop_ratio) and any(atk_loop_rate):
                if all(x == atk_loop_size[0] for x in atk_loop_size):
                    atk_info['loop size'] = atk_loop_size[0]
                else:
                    atk_info['loop size'] = atk_loop_size
                if all(x == atk_loop_count[0] for x in atk_loop_count):
                    atk_info['loop count'] = atk_loop_count[0]
                else:
                    atk_info['loop count'] = atk_loop_count
                if all(x == atk_loop_ratio[0] for x in atk_loop_ratio):
                    atk_info['loop ratio'] = atk_loop_ratio[0]
                else:
                    atk_info['loop ratio'] = atk_loop_ratio
                if all(x == atk_loop_rate[0] for x in atk_loop_rate):
                    atk_info['loop rate ratio'] = atk_loop_rate[0] / param.attack_volume / 125 / 1000 / 1000 * param.attack_tick_to_subtick
                else:
                    atk_info['loop rate ratio'] = [x / param.attack_volume / 125 / 1000 / 1000 * param.attack_tick_to_subtick for x in atk_loop_rate]
            if atk_info:
                ratio.append({atk: atk_info})
        result = {'attacks': ratio}
        inserted = False
        for r in atk_profile:
            if r[1] == result:
                r[0].append(tick)
                inserted = True
                break
        if not inserted:
            atk_profile.append([[tick], result])

    yaml_atk_profile = []
    for r in atk_profile:
        if len(r[0]) == 1:
            yaml_atk_profile.append({'tick' : r[0][0]})
            yaml_atk_profile.append(r[1])
        else:
            yaml_atk_profile.append({'tick' : r[0]})
            yaml_atk_profile.append(r[1])
    with open(f"{filename} attack profile.yaml", "w") as yaml_file:
        yaml.dump(yaml_atk_profile, yaml_file, default_flow_style=None, width=120)
