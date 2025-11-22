#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import math
from dup import *
from cerberus import calculate_shares, bits_used
from benign_ratio import packet_num_per_byte
import itertools
from functools import lru_cache
from tqdm import tqdm
from datetime import datetime
import json

d = Dup()
benign_max_collision_per_cms_entry = max(d.max_collision_per_cms_entry(True, ()))

# Calculate the slice length change given attack
def calculate_results(task_no: list[int], task_ip: list[list[list[int]]], task_ratio: list[int], dp_slice_length: list[int], is_print: bool) -> tuple[dict[int, list[int]], dict[int, int]]:
    task_num = len(task_no)
    if any(len(l) != task_num or any(any(lip[i-1] > lip[i] for i in range(1, len(lip))) for lip in l) for l in task_ip):
        raise ValueError(f"task_ip error: {task_ip}")
    if len(task_ratio) != task_num:
        raise ValueError(f"task_ratio error: {task_ratio}")
    if len(dp_slice_length) != task_num:
        raise ValueError(f"dp_slice_length error: {dp_slice_length}")
    dp_slice_length_history = {}
    uploaded_history = {}
    max_hit = [0] * task_num
    max_time = len(task_ip)

    if is_print:
        print(f"====================== {0} sec =====================")
        print(f"Slice length:\t{dp_slice_length}\n")
    dp_slice_length_history[0] = dp_slice_length

    for t in range(1, max_time + 1):
        if is_print:
            print(f"====================== {t} sec =====================")
        uploaded_history[t] = 0
        for i in range(task_num):
            ip = sum(task_ip[t-1][i][2*j+1] - task_ip[t-1][i][2*j] for j in range(len(task_ip[t-1][i])//2))
            uploaded_history[t] += iter_per_sec(10*task_ratio[i], dp_slice_length[i])*ip
        uploaded_history[t] /= 1000000
        if is_print:
            print(f"Uploaded_history:\t{uploaded_history[t]}M pps")

        # X: pps per IP
        avg_pkt = [2**(dp_slice_length[i]-1) * iter_per_sec(10*task_ratio[i], dp_slice_length[i]) for i in range(task_num)]
        # Y: max collision per CMS entry
        maxcol = [max(d.max_collision_per_cms_entry(False, sum([tuple(range(l[2*i], l[2*i+1])) for i in range(len(l)//2)], ()))) for l in task_ip[t-1]]

        # Z=X*Y: max hits for t seconds per CMS entry
        max_hit = [avg_pkt[i] * maxcol[i] + max_hit[i] for i in range(task_num)]
        max_hit = [max_hit[i] + packet_num_per_byte[task_no[i]]*1*125*1000*1000/30000*benign_max_collision_per_cms_entry for i in range(task_num)]
        if is_print:
            print(f"Max hit:\t{max_hit}")

        ideal_share = [dp_slice_length[i]-1 + bits_used(max_hit[i] // 2**(dp_slice_length[i]-1)) for i in range(len(max_hit))]
        if is_print:
            print(f"Ideal share:\t{ideal_share}")

        sorted_indices = sorted(range(task_num), key=lambda i: task_no[i])
        sorted_ideal_share = [ideal_share[i] for i in sorted_indices]
        sorted_dp_slice_length = calculate_shares(sum(dp_slice_length), sorted_ideal_share, True)
        dp_slice_length = [0] * task_num
        for sorted_idx, original_idx in enumerate(sorted_indices):
            dp_slice_length[original_idx] = sorted_dp_slice_length[sorted_idx]
        if is_print:
            print(f"Slice length:\t{dp_slice_length}\n")
        dp_slice_length_history[t] = dp_slice_length

    if is_print:
        print(f"Average uploaded:\t{sum(uploaded_history.values())/len(uploaded_history)}M pps")
    return dp_slice_length_history, uploaded_history

def test_combination_squeeze(task_num: int, dividend: int, is_perm: bool, is_save: bool):
    ip_num = 10000
    if task_num <= 0 or ip_num % dividend != 0 or task_num*5 > 32:
        raise ValueError(f"Wrong set of parameters (task_num, dividend): ({task_num}, {dividend})")

    all_task_no = [11, 5, 6, 13, 1][:4] # ordered in descending benign pps
    if task_num > len(all_task_no):
        raise ValueError(f"Add more all_task_no: {all_task_no}")
    num_exp = math.comb(dividend+task_num-1, task_num-1)**4
    pbar = tqdm(total=num_exp*math.perm(len(all_task_no), task_num)) if is_perm else tqdm(total=num_exp*math.comb(len(all_task_no), task_num))
    iter_indices = itertools.permutations(all_task_no, task_num) if is_perm else itertools.combinations(all_task_no, task_num)
    combination = {}
    for task_no in iter_indices:
        for partition0 in itertools.combinations_with_replacement(range(dividend + 1), task_num - 1):
            partition0 = (0,) + partition0 + (dividend,)
            partitioned_indices0 = [partition0[i]*(ip_num//dividend) for i in range(len(partition0))]
            partitioned_ip_num0 = tuple((partitioned_indices0[i+1] - partitioned_indices0[i]) for i in range(task_num))
            for partition1 in itertools.combinations_with_replacement(range(dividend + 1), task_num - 1):
                partition1 = (0,) + partition1 + (dividend,)
                partitioned_indices1 = [partition1[i]*(ip_num//dividend) for i in range(len(partition1))]
                partitioned_ip_num1 = tuple((partitioned_indices1[i+1] - partitioned_indices1[i]) for i in range(task_num))
                for partition2 in itertools.combinations_with_replacement(range(dividend + 1), task_num - 1):
                    partition2 = (0,) + partition2 + (dividend,)
                    partitioned_indices2 = [partition2[i]*(ip_num//dividend) for i in range(len(partition2))]
                    partitioned_ip_num2 = tuple((partitioned_indices2[i+1] - partitioned_indices2[i]) for i in range(task_num))
                    for partition3 in itertools.combinations_with_replacement(range(dividend + 1), task_num - 1):
                        partition3 = (0,) + partition3 + (dividend,)
                        partitioned_indices3 = [partition3[i]*(ip_num//dividend) for i in range(len(partition3))]
                        partitioned_ip_num3 = tuple((partitioned_indices3[i+1] - partitioned_indices3[i]) for i in range(task_num))

                        dp_slice_length_history, uploaded_history = calculate_results(task_no, [
                            [[partitioned_indices0[i], partitioned_indices0[i+1]] for i in range(task_num)],
                            [[partitioned_indices1[i], partitioned_indices1[i+1]] for i in range(task_num)],
                            [[partitioned_indices2[i], partitioned_indices2[i+1]] for i in range(task_num)],
                            [[partitioned_indices3[i], partitioned_indices3[i+1]] for i in range(task_num)]
                        ], [1] * task_num, [8, 8, 8, 8], False)

                        combination[tuple([task_no, partitioned_ip_num0, partitioned_ip_num1, partitioned_ip_num2, partitioned_ip_num3])] = dp_slice_length_history, uploaded_history
                        pbar.update()
    print(f"mean:\t{dict(sorted(combination.items(), key=lambda x: sum(x[1][1][t] for t in x[1][1]), reverse=True)[:10])}")

    if is_save:
        combination_json = {str(k): v for k, v in combination.items()}
        filename = f"results/calculate/({task_num}, {dividend}) {str(datetime.now()).replace(':', ';')}"
        with open(f"{filename}.json", "w") as file:
            json.dump(combination_json, file, indent=4)

        print(f"Results are saved at {filename}")
    else:
        print(f"Experiment finished at {datetime.now()}")

@lru_cache(maxsize=100)
def iter_per_sec(gbps: int, dp_slice_length: int) -> int:
    if dp_slice_length <= 1:
        raise ValueError(f"Not a valid dp_slice_length: {dp_slice_length}")

    bytes_per_iter = 64*2**(dp_slice_length-1)
    return round(gbps*125*1000*1000/10000/bytes_per_iter)

def linear_partition(seq, k):
    n = len(seq)
    if k <= 0:
        return []
    if k >= n:
        return [[x] for x in seq]

    # Initialize the DP tables
    table = [[0] * (k + 1) for _ in range(n + 1)]
    solution = [[0] * (k + 1) for _ in range(n + 1)]

    # Compute prefix sums
    prefix_sums = [0] * (n + 1)
    for i in range(1, n + 1):
        prefix_sums[i] = prefix_sums[i - 1] + seq[i - 1]

    # Base cases for DP
    for i in range(1, n + 1):
        table[i][1] = prefix_sums[i]
    for j in range(1, k + 1):
        table[1][j] = seq[0]

    # Fill DP tables
    for i in range(2, n + 1):
        for j in range(2, k + 1):
            best = None
            for x in range(1, i):
                cost = max(table[x][j - 1], prefix_sums[i] - prefix_sums[x])
                if best is None or cost < best:
                    best = cost
                    solution[i][j] = x
            table[i][j] = best

    # Reconstruct partitions from DP tables
    def reconstruct_partition(s, k):
        partitions = []
        while k > 1:
            idx = solution[s][k]
            partitions.insert(0, seq[idx:s])
            s = idx
            k -= 1
        partitions.insert(0, seq[0:s])
        return partitions

    return reconstruct_partition(n, k)

def reduce_to_size_count(sublists: list[list[int]]) -> tuple[list[list[int]], list[list[int]]]:
    sublists_size = [[] for _ in range(len(sublists))]
    sublists_count = [[] for _ in range(len(sublists))]
    for i in range(len(sublists)):
        for cur in sublists[i]:
            if not sublists_size[i] or sublists_size[i][-1] != cur:
                sublists_size[i].append(cur)
                sublists_count[i].append(1)
            else:
                sublists_count[i][-1] += 1
    return sublists_size, sublists_count

# not used; only used for atk_profile generation
def divide_to_subticks(dp_slice_length: int) -> tuple[list[list[int]], list[list[int]]]:
    num_iter = iter_per_sec(10, dp_slice_length)
    size = [64] * num_iter
    count = [2**(dp_slice_length-1)] * num_iter

    sublists = linear_partition(sum([[s]*c for s, c in zip(size, count)], []), 10)
    sublists_size, sublists_count = reduce_to_size_count(sublists)
    for i in range(10):
        print(f"Sublist {i + 1}: size={sublists_size[i]}, count={sublists_count[i]} (Sum: {sum(x*y for x, y in zip(sublists_size[i], sublists_count[i]))})")
    print("\n")
    print(f"Size={sublists_size}, redundant: {all(s == sublists_size[0] for s in sublists_size)}")
    print(f"Count={sublists_count}, redundant: {all(c == sublists_count[0] for c in sublists_count)}")

# optimization problem - when would the packet uploaded (%) be maximized
def optimize(total_share: int = 32, min_share: int = 5, n_task: int = 4):
    if min_share*n_task > total_share:
        raise ValueError(f"Wrong set of parameters (total_share, min_share, n_task): ({total_share}, {min_share}, {n_task})")

    result = {}
    max_val, max_index = 0, []
    cap_share = total_share - n_task*min_share      # 12
    for X in range(cap_share+1):                    # X can be 0 to 12
        for Y in range(cap_share+1 - X):            # Y can range so that X+Y <= 12
            for Z in range(cap_share+1 - X - Y):    # Similarly, ensure X+Y+Z <= 12
                W = cap_share - X - Y - Z
                # Now convert back to original variables
                x = X + min_share
                y = Y + min_share
                z = Z + min_share
                w = W + min_share
                result[(x, y, z, w)] = 2**(1-x) + 2**(1-y) + 2**(1-z) + 2**(1-w)
                if result[(x, y, z, w)] > max_val:
                    max_val = result[(x, y, z, w)]
                    max_index = [(x, y, z, w)]
                elif result[(x, y, z, w)] == max_val:
                    max_index.append((x, y, z, w))

    print(f"Max value: {max_val}, Max index: {max_index}")   # Max value: 0.1875152587890625, Max index: [(5, 5, 5, 17), (5, 5, 17, 5), (5, 17, 5, 5), (17, 5, 5, 5)]
    return result

def example_usage():    # Window not considered
    calculate_results([11, 5, 1, 13], [
        [[0, 10000], [0, 0], [0, 0], [0, 0]],
        [[0, 0], [0, 10000], [0, 0], [0, 0]],
        [[0, 0], [0, 0], [0, 10000], [0, 0]],
        [[0, 0], [0, 0], [0, 0], [0, 10000]],
    ], [1, 1, 1, 1], [8, 8, 8, 8], True)

if  __name__ == "__main__":
    # example_usage()

    ### Main Experiment ###
    task_num = 4
    dividend = 5
    test_combination_squeeze(task_num, dividend, True, False)

    # optimize()
