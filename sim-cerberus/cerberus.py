#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from common import *
import data_plane as dp
import control_plane as cp
import cms
from packet import packet as pkt
import params
import math

key_table = {
    0 : "src_ip",
    1 : "src_port",
    2 : "dst_ip",
    3 : "dst_port",
    4 : "protocol"
}

class Cerberus:
    def __init__(self, task_per_reg: list[list[int]], slice_per_registers: list[list[int]], cp_slice_per_tasks: list[int], array_size_per_registers: list[list[int]], elephant_array_sizes: list[list[int]], n_register: int, flowkey_table: dict, defense_table: dict, param: params.Params):
        # Ex) c = Cerberus([[0, 1, 2], [3, 4, 5, 6]], [[8, 8, 16], [8, 8, 8, 8]], [24, 24, 16, 24, 24, 24, 24], [[16, 16, 16], [16, 16, 16, 16]], [[13, 13, 13], [13, 13, 13, 13]], 2, ...)
        if (len(task_per_reg) != n_register) or (len(slice_per_registers) != n_register) or (len(array_size_per_registers) != n_register) or (len(elephant_array_sizes) != n_register):
            raise ValueError("Tasks per register or slice lengths or array sizes or elephant array sizes do not match the number of registers")
        for i in range(n_register):
            if (len(slice_per_registers[i]) != len(task_per_reg[i])) or (len(array_size_per_registers[i]) != len(task_per_reg[i])) or (elephant_array_sizes[i] and (len(elephant_array_sizes[i]) != len(task_per_reg[i]))):
                raise ValueError(f"Number of slice or elephant array sizes do not match number of tasks per register {i}")
        n_task_per_reg = [len(x) for x in task_per_reg]
        if len(cp_slice_per_tasks) != sum(n_task_per_reg):
            raise ValueError("Number of slice length does not match number of tasks")

        if param.adaptive_memory: # TODO: same array size is required in register
            for array_sizes in array_size_per_registers:
                for array_size in array_sizes:
                    if array_size != array_sizes[0]:
                        raise ValueError("For adaptive memory, array size must be same in a register")

        self.param = param
        self.task_per_reg = task_per_reg
        self.n_task = sum(n_task_per_reg)
        self.data_plane = dp.DataPlane(n_task_per_reg, slice_per_registers, array_size_per_registers, elephant_array_sizes, n_register, param.n_hash)
        self.control_plane = cp.ControlPlane(self.n_task, cp_slice_per_tasks, sum(array_size_per_registers, []), param.n_hash)
        self.blocklist = [cms.CountMinSketch(2, 2**param.blocklist_size, param.n_hash) for _ in range(2)]   # BF
        self.flowkey_table = flowkey_table
        self.defense_table = defense_table
        self.current_window = [0] * self.n_task
        self.hps_i = [dict() for _ in range(self.n_task)]
        self.rtps = [0] * self.n_task
        self.cb = [0] * self.n_task
        self.cp_max = [0] * self.n_task
        self.cp_max_bits = [0] * self.n_task

        task_bf = [key for key, value in flowkey_table.items() if value[4]]
        self.adaptive_task_per_reg = [list_difference(l, task_bf)[0] for l in task_per_reg] # except bloom filter

        # Statistics
        self.bandwidth_utilization = 0  # TODO: bandwidth only concerns recirculated packets from overflow
        self.overflowed_packet = [0] * (self.n_task + 1)
        self.uploaded_packet = [0] * (self.n_task + 1)
        self.num_packet = [0] * (self.n_task + 1)
        self.bandwidth_utilization_history = []
        self.overflowed_packet_ratio_history = [[] for _ in range(self.n_task + 1)]
        self.uploaded_packet_history = [[] for _ in range(self.n_task + 1)]
        self.uploaded_packet_ratio_history = [[] for _ in range(self.n_task + 1)]
        self.counter_size_history = [[] for _ in range(self.n_task)]
        self.cp_max_history = [[] for _ in range(self.n_task)]
        self.cp_max_bits_history = [[] for _ in range(self.n_task)]
        self.cp_not_processed_packet = 0
        self.cp_not_processed_packet_history = []

    def find_task(self, task_id: int) -> tuple[int, int]:
        reg_index = 0
        for task_ids in self.task_per_reg:
            if (task_id < len(task_ids)):
                return reg_index, task_id
            task_id -= len(task_ids)
            reg_index += 1
        raise ValueError("task_id exceeds number of tasks")

    def update(self, p: pkt.Packet) -> list[bool]:
        # defense
        c2_key = calculate_flowkey(["src_ip", "dst_ip"], p)
        blocked = [bool(min(self.blocklist[i].read(c2_key))) for i in range(2)]

        overflow = [False] * self.n_task
        blocklist_update_request = [False] * self.n_task
        cp_active = self.bandwidth_utilization <= self.param.cp_processing_threshold / self.param.tick_divisor
        for task_id in sum(self.task_per_reg, []):
            condition_key, task_key, task_action, task_value, _ = self.flowkey_table[task_id]
            defense_condition_key, defense_task_key, threshold, _, _ = self.defense_table[task_id]
            condition, flow_key = find_flowkey(condition_key, task_key, p)
            defense_condition, defense_flow_key = find_flowkey(defense_condition_key, defense_task_key, p)
            # update CMS and blocklist; it is True only if it is update to CMS or (non-attack) BF
            if condition:
                amount = p.packet_size if task_value == 0 else task_value
                for operation in task_action:
                    overflow[task_id], blocklist_update_request[task_id] = self.update_task(task_id, operation, flow_key, amount, p.packet_size, cp_active, threshold, defense_condition and task_key == defense_task_key and (not blocked[self.current_window[0]]))
            # update blocklist (when not updating CMS); it is True only if it is defense to (attack) BF
            elif defense_condition:
                reg_index, task_index = self.find_task(task_id)
                if self.data_plane.read_all(reg_index, task_index, defense_flow_key) < threshold / 2**self.param.shrink_ratio_exp:
                    blocklist_update_request[task_id] = not blocked[self.current_window[0]]

            if overflow[task_id]:
                self.overflowed_packet[task_id] += 1
            if overflow[task_id] or blocklist_update_request[task_id]:
                self.uploaded_packet[task_id] += 1
            if condition or defense_condition:
                self.num_packet[task_id] += 1

        if cp_active and any(blocklist_update_request):
            self.blocklist[self.current_window[0]].setbit(c2_key, 1, False)
            blocked[self.current_window[0]] = True

        if any(overflow):
            self.overflowed_packet[self.n_task] += 1
        if any(overflow) or any(blocklist_update_request):
            self.bandwidth_utilization += p.packet_size
            self.uploaded_packet[self.n_task] += 1
        if not cp_active:
            self.cp_not_processed_packet += 1
        self.num_packet[self.n_task] += 1
        return blocked

    # df_active is True only if it is CMS (not BF) for now; hence block request if value >= threhsold
    def update_task(self, task: int, operation: str, element, value: int, packet_size: int, cp_active: bool, threshold: int, df_active: bool) -> tuple[bool, bool]:
        blocklist_update_request = False
        reg_index, task_index = self.find_task(task)
        overflow_value, data_plane_data = self.data_plane.update_register(reg_index, task_index, operation, element, value, self.current_window[task])
        diff_data_plane_data = self.data_plane.read(reg_index, task_index, element, self.current_window[task])
        if df_active and sum([min(data_plane_data), min(diff_data_plane_data)]) >= threshold / 2**self.param.shrink_ratio_exp:
            blocklist_update_request = True

        if cp_active and any(overflow_value):
            control_plane_data = self.control_plane.co_monitoring(task, element, overflow_value, operation, self.current_window[task])
            diff_control_plane_data = self.control_plane.read(task, element, self.current_window[task])
            # Calc current data
            # data = self.read(task, element)
            # Update HPS
            hps_ij = self.calc_hps_ij(task, min([overflow_value[i] for i in min_indices(list_elementwise_sub(control_plane_data, overflow_value))]), packet_size)
            if element not in self.hps_i[task]:
                self.hps_i[task][element] = hps_ij
            else:
                self.hps_i[task][element] += hps_ij
            self.rtps[task] += hps_ij
            self.cb[task] += hps_ij*packet_size

            cp_max = max(control_plane_data)
            max_bit = intlog2(cp_max)+1 if cp_max > 0 else 0
            self.cp_max[task] = max(self.cp_max[task], cp_max)
            self.cp_max_bits[task] = max(self.cp_max_bits[task], max_bit)

            if df_active and sum([min(control_plane_data), min(diff_control_plane_data)]) * 2**(self.data_plane.register[self.current_window[task]][reg_index].cms[task_index].counter_size-1) >= threshold / 2**self.param.shrink_ratio_exp:
                blocklist_update_request = True

        return any(overflow_value), blocklist_update_request

    def update_subtick(self, subtick: int):
        # statistics
        if (subtick + 1) % self.param.statistics_cycle_subtick == 0:
            self.collect_statistics_subtick()

    def update_tick(self, tick: int):
        # choose top-k for elephant region
        if self.param.elephant_region and (tick + 1) % self.param.elephant_cycle == 0 and self.data_plane.register[0][0].elephant_region:
            self.change_top_k()

        # statistics
        if (tick + 1) % self.param.statistics_cycle_tick == 0:
            self.collect_statistics_tick()

        # adaptive memory
        if self.param.adaptive_memory and (tick + 1) % self.param.adaptive_memory_cycle == 0:
            self.change_adaptive_memory()

        # window change
        for task_id in sum(self.task_per_reg, []):
            if (tick + 1) % self.param.refresh_cycle[task_id] == 0:
                self.change_current_window(task_id)

    def read(self, task: int, element) -> int:
        reg_index, task_index = self.find_task(task)
        data_plane_data = self.data_plane.read(reg_index, task_index, element, self.current_window[task])
        control_plane_data = self.control_plane.read(task, element, self.current_window[task])
        data = min(list_elementwise_add(data_plane_data, [x * (2**(self.data_plane.register[(self.current_window[task]-1) % 2][reg_index].cms[task_index].counter_size-1)) for x in control_plane_data]))
        return data

    def change_adaptive_memory(self):
        for reg_index in range(len(self.adaptive_task_per_reg)):
            if len(self.adaptive_task_per_reg[reg_index]) > 1:
                current_counter_sizes = [0] * len(self.adaptive_task_per_reg[reg_index])
                ideal_shares = [0] * len(self.adaptive_task_per_reg[reg_index])
                new_array_sizes = [0] * len(self.adaptive_task_per_reg[reg_index])
                for adaptive_task_index in range(len(self.adaptive_task_per_reg[reg_index])):
                    task_id = self.adaptive_task_per_reg[reg_index][adaptive_task_index]
                    _, task_index = self.find_task(task_id)
                    current_counter_sizes[adaptive_task_index] = self.data_plane.register[self.current_window[task_id]][reg_index].cms[task_index].counter_size
                    ideal_shares[adaptive_task_index] = current_counter_sizes[adaptive_task_index]-1 + bits_used(self.cp_max[task_id])
                    new_array_sizes[adaptive_task_index] = intlog2(self.data_plane.register[self.current_window[task_id]][reg_index].cms[task_index].cms_array_size)
                register_size = sum(current_counter_sizes)
                base_shares = calculate_shares(register_size, ideal_shares, True)

                slicings = list_elementwise_sub(base_shares, current_counter_sizes)
                self.resize(self.adaptive_task_per_reg[reg_index], slicings, new_array_sizes)
                for adaptive_task_index in range(len(self.adaptive_task_per_reg[reg_index])):
                    task_id = self.adaptive_task_per_reg[reg_index][adaptive_task_index]
                    self.cp_max[task_id] = self.cp_max[task_id] * 2**(-slicings[adaptive_task_index])
                    self.cp_max_bits[task_id] = relu(self.cp_max_bits[task_id] - slicings[adaptive_task_index])

    def resize(self, task_ids: list[int], slicings: list[int], array_sizes: list[int]):
        # e.g., task_ids: [0, 1, 2, 3], slicings: [1, 2, -3, 0] means:
        #   size of cms in dataplane of task0 increase 1 bit: need to send 1 bit to dataplane
        #   size of cms in dataplane of task1 increase 2 bits: need to send 2 bits to dataplane
        #   size of cms in dataplane of task1 decrease 3 bits: controlplane will receive 3 bits from dataplane
        for w in range(2):
            for i in range(len(task_ids)):
                task_id = task_ids[i]
                reg_index, task_index = self.find_task(task_id)
                sending_data = [[]]

                self.control_plane.cms[w][task_id].resize_bucket(0, 2**array_sizes[i], [[]])

                if slicings[i] > 0:     # send data to data plane
                    sending_data = self.control_plane.send_to_dataplane(w, task_id, slicings[i])

                received_data = self.data_plane.register[w][reg_index].resize_cms(task_index, slicings[i], 2**array_sizes[i], sending_data)

                if slicings[i] < 0:   # receive data from data plane
                    self.control_plane.receive_from_dataplane(w, task_id, slicings[i], received_data)

        # for reg_index in range(len(self.task_per_reg)):
        #     for window in range(2):
        #         self.data_plane.register[window][reg_index].integrity_check()

    def collect_statistics_subtick(self):
        self.bandwidth_utilization_history.append(self.bandwidth_utilization / (self.param.statistics_cycle_subtick/self.param.tick_divisor) / self.param.data_to_control_channel_bandwidth * 100)
        for task in range(self.n_task + 1):
            self.uploaded_packet_history[task].append(self.uploaded_packet[task]/1000000*10 * 2**self.param.shrink_ratio_exp)
            if self.num_packet[task] != 0:
                self.overflowed_packet_ratio_history[task].append(self.overflowed_packet[task] / self.num_packet[task] * 100)
                self.uploaded_packet_ratio_history[task].append(self.uploaded_packet[task] / self.num_packet[task] * 100)
            else:
                self.overflowed_packet_ratio_history[task].append(0)
                self.uploaded_packet_ratio_history[task].append(0)
        if self.num_packet[self.n_task] != 0:
            self.cp_not_processed_packet_history.append(self.cp_not_processed_packet / self.num_packet[self.n_task] * 100)
        else:
            self.cp_not_processed_packet_history.append(0)
        self.cp_not_processed_packet = 0
        self.bandwidth_utilization = 0
        self.overflowed_packet = [0] * (self.n_task + 1)
        self.uploaded_packet = [0] * (self.n_task + 1)
        self.num_packet = [0] * (self.n_task + 1)

    def collect_statistics_tick(self):
        for task in range(self.n_task):
            reg_index, task_index = self.find_task(task)
            self.counter_size_history[task].append(self.data_plane.register[self.current_window[task]][reg_index].cms[task_index].counter_size)
            self.cp_max_history[task].append(self.cp_max[task])
            self.cp_max_bits_history[task].append(self.cp_max_bits[task])

    def change_current_window(self, task_id: int):
        self.current_window[task_id] = (self.current_window[task_id] + 1) % 2
        self.clear_register(task_id)
        self.hps_i = [dict() for _ in range(self.n_task)]
        self.rtps = [0] * self.n_task
        self.cb = [0] * self.n_task

    def clear_register(self, task_id: int):
        cms = self.control_plane.cms[self.current_window[task_id]][task_id]
        for i in range(cms.depth):
            for j in range(cms.cms_array_size):
                cms.cms[i][j] = 0
        self.cp_max[task_id] = 0
        self.cp_max_bits[task_id] = 0

        reg_index, _ = self.find_task(task_id)
        reg = self.data_plane.register[self.current_window[task_id]][reg_index]
        for cms in reg.cms:
            for i in range(cms.depth):
                for j in range(cms.cms_array_size):
                    cms.cms[i][j] = 0
        if reg.elephant_region:
            reg.elephant_region = [{} for _ in range(reg.n_task)]

        if task_id == 0:
            for i in range(self.blocklist[self.current_window[0]].depth):
                for j in range(self.blocklist[self.current_window[0]].cms_array_size):
                    self.blocklist[self.current_window[0]].cms[i][j] = 0

    def change_top_k(self):
        for task in range(self.n_task):
            reg_index, task_index = self.find_task(task)
            top_k_keys = self.top_k_keys_with_largest_values(task, reg_index, task_index)

            inserted_keys, evicted_keys = list_difference(top_k_keys, self.data_plane.register[self.current_window[task]][reg_index].elephant_region[task_index].keys())

            received_data = self.data_plane.change_top_k(reg_index, task_index, inserted_keys, evicted_keys, self.current_window[task])

            self.control_plane.receive_from_dataplane_elephant(task, received_data, self.current_window[task])

    def top_k_keys_with_largest_values(self, task: int, reg_index: int, task_index: int) -> list:
        d = self.hps_i[task]
        k = self.data_plane.register[self.current_window[task]][reg_index].elephant_array_sizes[task_index]
        sorted_items = sorted(d.items(), key=lambda item: item[1], reverse=True)[:k]
        top_k_keys = [item[0] for item in sorted_items]
        return top_k_keys

    def calc_hps_ij(self, task_id: int, cp_data: int, packet_size: int) -> int:
        # Calculate per flow HPS
        control_plane_data = relu(math.floor(cp_data))
        _, _, _, value, _ = self.flowkey_table[task_id]
        if value == 0:
            hps_ij = control_plane_data / (self.param.refresh_cycle[task_id]*packet_size)
        else:
            hps_ij = control_plane_data / (self.param.refresh_cycle[task_id]*value)
        return hps_ij

def find_flowkey(condition_keys: list[list], task_key: list[str], p: pkt.Packet) -> tuple[bool, bytes]:
    for condition_key in condition_keys:
        condition = True
        for i in sorted(key_table):
            if condition_key[i] == None:
                continue
            elif (not isinstance(condition_key[i], str) and condition_key[i] != p.get(key_table[i])) or (isinstance(condition_key[i], str) and not p.get(key_table[i]).startswith(condition_key[i])):
                condition = False
        if condition:
            return True, calculate_flowkey(task_key, p)
    return False, bytes(0)

def calculate_flowkey(task_key: list[str], p: pkt.Packet) -> bytes:
    flow_key = []
    for key in task_key:
        flow_key.append(p.get(key))
    return bytes().join(flow_key)

def calculate_shares(register_size: int, ideal_shares: list[float], is_min_share: bool):
    if is_min_share:
        min_share = 5
        if min_share*len(ideal_shares) > register_size:
            raise ValueError("Cannot distribute shares while respecting the minimum share and total sum requirement.")

    denom = sum(ideal_shares)
    denom = denom if denom > 0 else 1
    effective_register_size = register_size - len(ideal_shares)
    ideal_shares = [x / denom * effective_register_size for x in ideal_shares]
    base_shares = [math.floor(x) for x in ideal_shares]
    remaining = effective_register_size - sum(base_shares)
    decimals = list_elementwise_sub(ideal_shares, base_shares)
    while remaining > 0:
        sorted_indices = sorted(range(len(decimals)), key=lambda i: decimals[i], reverse=True)
        base_shares[sorted_indices[0]] += 1
        decimals[sorted_indices[0]] -= 1
        remaining -= 1

    if is_min_share:
        min_share -= 1
        deficit = 0
        for i in range(len(base_shares)):
            if base_shares[i] < min_share:
                deficit += (min_share - base_shares[i])
                base_shares[i] = min_share
                decimals[i] = float('inf')
        while deficit > 0:
            sorted_indices = sorted(range(len(decimals)), key=lambda i: (decimals[i], -base_shares[i]))
            for i in range(len(base_shares)):
                if base_shares[sorted_indices[i]] > min_share:
                    base_shares[sorted_indices[i]] -= 1
                    decimals[sorted_indices[i]] += 1
                    deficit -= 1
                    break

    return [x + 1 for x in base_shares]

def relu(x: int) -> int:
    return max(0, x)

def intlog2(n: int) -> int:
    if n <= 0:
        raise ValueError("Input must be a positive integer.")

    result = 0
    while n > 1:
        n //= 2
        result += 1
    return result

def bits_used(n: int) -> float:
    return math.log2(n)+1 if n > 0 else 0

def min_indices(lst):
    min_value = min(lst)
    return [i for i, x in enumerate(lst) if x == min_value]
